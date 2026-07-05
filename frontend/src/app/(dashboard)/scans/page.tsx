'use client';

import { Button, Chip } from '@mui/material';
import { PlayArrow } from '@mui/icons-material';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { scansApi } from '@/lib/api';
import { MOCK_SCANS, paginate } from '@/lib/mock-data';
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
        <Chip label={`C:${row.critical_count}`} size="small" color="error" sx={{ mr: 0.5 }} />
        <Chip label={`H:${row.high_count}`} size="small" color="warning" sx={{ mr: 0.5 }} />
        <Chip label={`M:${row.medium_count}`} size="small" />
      </span>
    ),
  },
  { id: 'started_at', label: 'Started', getValue: (row) => row.started_at ? new Date(row.started_at).toLocaleString() : '—' },
  { id: 'duration_seconds', label: 'Duration', getValue: (row) => row.duration_seconds ? `${Math.round(row.duration_seconds / 60)}m` : '—' },
];

export default function ScansPage() {
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);

  const { data, isLoading } = useQuery({
    queryKey: ['scans', page, pageSize],
    queryFn: async () => {
      try {
        return await scansApi.list({ page: page + 1, page_size: pageSize });
      } catch {
        return paginate(MOCK_SCANS, page + 1, pageSize);
      }
    },
  });

  return (
    <>
      <PageHeader
        title="Scans"
        subtitle="Manage vulnerability and compliance scans"
        action={<Button variant="contained" startIcon={<PlayArrow />}>New Scan</Button>}
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
      />
    </>
  );
}
