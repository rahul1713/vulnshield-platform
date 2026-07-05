'use client';

import { Button } from '@mui/material';
import { Description } from '@mui/icons-material';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { reportsApi } from '@/lib/api';
import { MOCK_REPORTS, paginate } from '@/lib/mock-data';
import { PageHeader } from '@/components/ui/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { StatusChip } from '@/components/ui/SeverityChip';
import { Report } from '@/types';

const columns: Column<Report>[] = [
  { id: 'name', label: 'Report Name', sortable: true },
  { id: 'report_type', label: 'Type', render: (row) => row.report_type.replace(/_/g, ' ') },
  { id: 'format', label: 'Format', render: (row) => row.format.toUpperCase() },
  { id: 'status', label: 'Status', render: (row) => <StatusChip status={row.status} /> },
  { id: 'generated_at', label: 'Generated', getValue: (row) => row.generated_at ? new Date(row.generated_at).toLocaleString() : '—' },
  { id: 'created_at', label: 'Created', getValue: (row) => new Date(row.created_at).toLocaleDateString() },
];

export default function ReportsPage() {
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);

  const { data, isLoading } = useQuery({
    queryKey: ['reports', page, pageSize],
    queryFn: async () => {
      try {
        return await reportsApi.list({ page: page + 1, page_size: pageSize });
      } catch {
        return paginate(MOCK_REPORTS, page + 1, pageSize);
      }
    },
  });

  return (
    <>
      <PageHeader
        title="Reports"
        subtitle="Generate and download security reports"
        action={<Button variant="contained" startIcon={<Description />}>Generate Report</Button>}
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
      />
    </>
  );
}
