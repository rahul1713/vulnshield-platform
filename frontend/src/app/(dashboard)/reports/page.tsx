'use client';

import { Button, Stack } from '@mui/material';
import { Description, PictureAsPdf } from '@mui/icons-material';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { reportsApi } from '@/lib/api';
import { PageHeader } from '@/components/ui/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { StatusChip } from '@/components/ui/SeverityChip';
import { Report } from '@/types';
import { isDemoSession } from '@/lib/api-client-helpers';
import { downloadPdfBlob, generateExecutivePdf } from '@/lib/executive-pdf';
import { useToast } from '@/components/ui/ToastProvider';

const columns: Column<Report>[] = [
  { id: 'name', label: 'Report Name', sortable: true },
  { id: 'report_type', label: 'Type', render: (row) => row.report_type.replace(/_/g, ' ') },
  { id: 'format', label: 'Format', render: (row) => row.format.toUpperCase() },
  { id: 'status', label: 'Status', render: (row) => <StatusChip status={row.status} /> },
  { id: 'generated_at', label: 'Generated', getValue: (row) => row.generated_at ? new Date(row.generated_at).toLocaleString() : '—' },
];

export default function ReportsPage() {
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const { showToast } = useToast();

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['reports', page, pageSize],
    queryFn: () => reportsApi.list({ page: page + 1, page_size: pageSize }),
    refetchInterval: 5000,
  });

  const handleExecutiveReport = async () => {
    try {
      if (isDemoSession()) {
        const inputs = Object.values(
          JSON.parse(sessionStorage.getItem('vulnshield_demo_report_inputs') || '{}')
        );
        if (!inputs.length) {
          showToast('Run a scan or review first to generate data', 'warning');
          return;
        }
        const blob = generateExecutivePdf(inputs[0] as Parameters<typeof generateExecutivePdf>[0]);
        downloadPdfBlob(blob, 'vulnshield-executive-summary.pdf');
      } else {
        const report = await reportsApi.generate({
          name: 'Organization Executive Summary',
          report_type: 'executive',
          format: 'pdf',
        });
        await reportsApi.download(report.id, 'executive-summary.pdf');
      }
      showToast('Report downloaded', 'success');
      refetch();
    } catch (e) {
      showToast(e instanceof Error ? e.message : 'Failed to generate report', 'error');
    }
  };

  const downloadRow = async (row: Report) => {
    try {
      if (isDemoSession()) {
        const map = JSON.parse(sessionStorage.getItem('vulnshield_demo_report_inputs') || '{}');
        const first = Object.values(map)[0];
        if (first) {
          downloadPdfBlob(generateExecutivePdf(first as Parameters<typeof generateExecutivePdf>[0]), `${row.name}.pdf`);
        }
      } else {
        await reportsApi.download(row.id, `${row.name}.pdf`);
      }
      showToast('PDF downloaded', 'success');
    } catch (e) {
      showToast(e instanceof Error ? e.message : 'Download failed', 'error');
    }
  };

  return (
    <>
      <PageHeader
        title="Reports"
        subtitle="Executive PDF reports from scans, SAST, DAST, and red team assessments"
        action={
          <Button variant="contained" startIcon={<Description />} onClick={handleExecutiveReport}>
            Generate Executive Summary
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
        searchPlaceholder="Search reports..."
        getRowId={(row) => row.id}
        rowActions={(row) => (
          <Stack direction="row" justifyContent="flex-end">
            {row.status === 'completed' && row.format === 'pdf' && (
              <Button size="small" startIcon={<PictureAsPdf />} onClick={() => downloadRow(row)}>
                Download
              </Button>
            )}
          </Stack>
        )}
      />
    </>
  );
}
