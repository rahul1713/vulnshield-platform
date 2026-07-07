'use client';

import { Button } from '@mui/material';
import { Security } from '@mui/icons-material';
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { redTeamApi } from '@/lib/api';
import { PageHeader } from '@/components/ui/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { StatusChip } from '@/components/ui/SeverityChip';
import { CreateRedTeamDialog } from '@/components/red-team/CreateRedTeamDialog';
import { ReportDownloadButton } from '@/components/reports/ReportDownloadButton';
import { useToast } from '@/components/ui/ToastProvider';
import { RedTeamCampaign } from '@/types';
import { Stack } from '@mui/material';

const columns: Column<RedTeamCampaign>[] = [
  { id: 'name', label: 'Campaign', sortable: true },
  { id: 'description', label: 'Description', getValue: (row) => row.description || '—' },
  { id: 'status', label: 'Status', render: (row) => <StatusChip status={row.status} /> },
  { id: 'findings_count', label: 'Findings', sortable: true },
  { id: 'started_at', label: 'Started', getValue: (row) => row.started_at ? new Date(row.started_at).toLocaleDateString() : '—' },
  { id: 'completed_at', label: 'Completed', getValue: (row) => row.completed_at ? new Date(row.completed_at).toLocaleDateString() : '—' },
];

export default function RedTeamPage() {
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [dialogOpen, setDialogOpen] = useState(false);
  const queryClient = useQueryClient();
  const { showToast } = useToast();

  const { data, isLoading } = useQuery({
    queryKey: ['red-team', page, pageSize],
    queryFn: () => redTeamApi.list({ page: page + 1, page_size: pageSize }),
    refetchInterval: 3000,
  });

  const createMutation = useMutation({
    mutationFn: ({ name, description }: { name: string; description: string }) =>
      redTeamApi.create(name, description),
    onSuccess: () => {
      showToast('Campaign complete — executive PDF report ready', 'success');
      queryClient.invalidateQueries({ queryKey: ['red-team'] });
      queryClient.invalidateQueries({ queryKey: ['reports'] });
    },
    onError: (e: Error) => showToast(e.message, 'error'),
  });

  return (
    <>
      <PageHeader
        title="AI Red Team"
        subtitle="MITRE ATT&CK adversary simulation with executive PDF reports"
        action={
          <Button variant="contained" startIcon={<Security />} onClick={() => setDialogOpen(true)}>
            New Campaign
          </Button>
        }
      />
      <DataTable
        columns={columns}
        data={data?.items ?? []}
        total={data?.total ?? 0}
        loading={isLoading}
        page={page}
        pageSize={pageSize}
        onPageChange={setPage}
        onPageSizeChange={setPageSize}
        searchPlaceholder="Search campaigns..."
        getRowId={(row) => row.id}
        rowActions={(row) => (
          <Stack direction="row" justifyContent="flex-end">
            {row.status === 'completed' && (
              <ReportDownloadButton
                filename={`redteam-report-${row.name}.pdf`}
                demoReportKey={`redteam:${row.id}`}
                entityType="redteam"
                entityId={row.id}
                label="PDF"
              />
            )}
          </Stack>
        )}
      />
      <CreateRedTeamDialog
        open={dialogOpen}
        onClose={() => setDialogOpen(false)}
        onSubmit={async (name, description) => {
          await createMutation.mutateAsync({ name, description });
        }}
      />
    </>
  );
}
