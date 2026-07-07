'use client';

import { Button, IconButton, Stack } from '@mui/material';
import { PlayArrow, Stop } from '@mui/icons-material';
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { scansApi } from '@/lib/api';
import { isDemoSession } from '@/lib/api-client-helpers';
import { waitForDemoScanComplete } from '@/lib/demo-helpers';
import { useToast } from '@/components/ui/ToastProvider';
import { CreateScanDialog } from '@/components/scans/CreateScanDialog';
import { ReportDownloadButton } from '@/components/reports/ReportDownloadButton';
import { PageHeader } from '@/components/ui/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { StatusChip } from '@/components/ui/SeverityChip';
import { Scan } from '@/types';

const columns: Column<Scan>[] = [
  { id: 'name', label: 'Scan Name', sortable: true },
  { id: 'scan_type', label: 'Type', render: (row) => row.scan_type.replace(/_/g, ' ') },
  { id: 'status', label: 'Status', render: (row) => <StatusChip status={row.status} /> },
  { id: 'findings_count', label: 'Findings', sortable: true },
  {
    id: 'severity_breakdown',
    label: 'Breakdown',
    render: (row) => (
      <span className="text-xs">
        C:{row.critical_count} H:{row.high_count} M:{row.medium_count}
      </span>
    ),
  },
  { id: 'started_at', label: 'Started', getValue: (row) => row.started_at ? new Date(row.started_at).toLocaleString() : '—' },
];

export default function ScansPage() {
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [dialogOpen, setDialogOpen] = useState(false);
  const queryClient = useQueryClient();
  const { showToast } = useToast();

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['scans', page, pageSize],
    queryFn: () => scansApi.list({ page: page + 1, page_size: pageSize }),
    refetchInterval: 3000,
  });

  const notifyScanComplete = async (scanId: string, scanName: string) => {
    if (isDemoSession()) {
      const ready = await waitForDemoScanComplete(scanId);
      if (!ready) {
        showToast('Scan is still running — PDF will be available shortly', 'info');
        return;
      }
    }
    showToast(`Scan "${scanName}" completed — executive PDF ready`, 'success');
    queryClient.invalidateQueries({ queryKey: ['scans'] });
    queryClient.invalidateQueries({ queryKey: ['reports'] });
  };

  const startMutation = useMutation({
    mutationFn: (id: string) => scansApi.start(id),
    onSuccess: async (scan) => {
      await notifyScanComplete(scan.id, scan.name);
    },
    onError: (e: Error) => showToast(e.message, 'error'),
  });

  const cancelMutation = useMutation({
    mutationFn: (id: string) => scansApi.cancel(id),
    onSuccess: () => {
      showToast('Scan cancelled', 'info');
      queryClient.invalidateQueries({ queryKey: ['scans'] });
    },
  });

  const handleCreate = async (payload: { name: string; scan_type: Scan['scan_type']; target_asset_id?: string }) => {
    try {
      const scan = await scansApi.create(payload);
      showToast(`Scan "${scan.name}" created`, 'success');
      await refetch();
      if (scan.id) {
        const started = await scansApi.start(scan.id);
        await notifyScanComplete(started.id, started.name);
      }
    } catch (e) {
      showToast(e instanceof Error ? e.message : 'Failed to create scan', 'error');
      throw e;
    }
  };

  return (
    <>
      <PageHeader
        title="Scans"
        subtitle="Vulnerability assessments with executive PDF reports"
        action={
          <Button variant="contained" startIcon={<PlayArrow />} onClick={() => setDialogOpen(true)}>
            New Scan
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
        searchPlaceholder="Search scans..."
        getRowId={(row) => row.id}
        rowActions={(row) => (
          <Stack direction="row" spacing={0.5} justifyContent="flex-end" alignItems="center">
            {row.status === 'completed' && (
              <ReportDownloadButton
                filename={`scan-report-${row.name}.pdf`}
                demoReportKey={`scan:${row.id}`}
                entityType="scan"
                entityId={row.id}
                label="PDF"
              />
            )}
            {(row.status === 'queued' || row.status === 'failed') && (
              <IconButton size="small" color="primary" title="Start scan" onClick={() => startMutation.mutate(row.id)}>
                <PlayArrow fontSize="small" />
              </IconButton>
            )}
            {row.status === 'running' && (
              <IconButton size="small" color="warning" title="Cancel" onClick={() => cancelMutation.mutate(row.id)}>
                <Stop fontSize="small" />
              </IconButton>
            )}
          </Stack>
        )}
      />
      <CreateScanDialog open={dialogOpen} onClose={() => setDialogOpen(false)} onSubmit={handleCreate} />
    </>
  );
}
