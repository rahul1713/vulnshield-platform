'use client';

import { Button, Stack } from '@mui/material';
import { PlayArrow } from '@mui/icons-material';
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { webScannerApi } from '@/lib/api';
import { PageHeader } from '@/components/ui/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { SeverityChip, SimulatedBadge } from '@/components/ui/SeverityChip';
import { StartWebScanDialog } from '@/components/web-scanner/StartWebScanDialog';
import { ReportDownloadButton } from '@/components/reports/ReportDownloadButton';
import { useToast } from '@/components/ui/ToastProvider';
import { WebScanFinding } from '@/types';

const columns: Column<WebScanFinding>[] = [
  {
    id: 'title',
    label: 'Finding',
    sortable: true,
    render: (row) => (
      <>
        {row.title}
        {row.is_simulated && <SimulatedBadge />}
      </>
    ),
  },
  { id: 'url', label: 'URL' },
  { id: 'vulnerability_type', label: 'Type' },
  { id: 'owasp_category', label: 'OWASP', getValue: (row) => row.owasp_category || '—' },
  { id: 'severity', label: 'Severity', render: (row) => <SeverityChip severity={row.severity} /> },
  { id: 'created_at', label: 'Found', getValue: (row) => new Date(row.created_at).toLocaleDateString() },
];

export default function WebScannerPage() {
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [lastScanUrl, setLastScanUrl] = useState('');
  const queryClient = useQueryClient();
  const { showToast } = useToast();

  const { data, isLoading } = useQuery({
    queryKey: ['web-scanner', page, pageSize],
    queryFn: () => webScannerApi.listFindings({ page: page + 1, page_size: pageSize }),
  });

  const scanMutation = useMutation({
    mutationFn: (url: string) => webScannerApi.startScan(url),
    onSuccess: (_, url) => {
      setLastScanUrl(url);
      showToast('Web scan complete — download DAST PDF report', 'success');
      queryClient.invalidateQueries({ queryKey: ['web-scanner'] });
      queryClient.invalidateQueries({ queryKey: ['reports'] });
    },
    onError: (e: Error) => showToast(e.message, 'error'),
  });

  return (
    <>
      <PageHeader
        title="Web Scanner"
        subtitle="DAST with OWASP Top 10 testing and executive PDF reports"
        action={
          <Stack direction="row" spacing={1}>
            {lastScanUrl && (
              <ReportDownloadButton
                label="Download PDF"
                filename="dast-report.pdf"
                demoReportKey={`webscan:${lastScanUrl}`}
                entityType="webscan"
                variant="outlined"
              />
            )}
            <Button variant="contained" startIcon={<PlayArrow />} onClick={() => setDialogOpen(true)}>
              Start Web Scan
            </Button>
          </Stack>
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
        searchPlaceholder="Search web findings..."
        getRowId={(row) => row.id}
      />
      <StartWebScanDialog
        open={dialogOpen}
        onClose={() => setDialogOpen(false)}
        onSubmit={async (url) => {
          await scanMutation.mutateAsync(url);
        }}
      />
    </>
  );
}
