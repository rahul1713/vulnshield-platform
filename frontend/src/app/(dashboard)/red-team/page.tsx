'use client';

import { Button } from '@mui/material';
import { Security } from '@mui/icons-material';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { redTeamApi } from '@/lib/api';
import { MOCK_RED_TEAM, paginate } from '@/lib/mock-data';
import { PageHeader } from '@/components/ui/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { StatusChip } from '@/components/ui/SeverityChip';
import { RedTeamCampaign } from '@/types';

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

  const { data, isLoading } = useQuery({
    queryKey: ['red-team', page, pageSize],
    queryFn: async () => {
      try {
        return await redTeamApi.list({ page: page + 1, page_size: pageSize });
      } catch {
        return paginate(MOCK_RED_TEAM, page + 1, pageSize);
      }
    },
  });

  return (
    <>
      <PageHeader
        title="AI Red Team"
        subtitle="Automated adversary simulation and attack path analysis"
        action={<Button variant="contained" startIcon={<Security />}>New Campaign</Button>}
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
      />
    </>
  );
}
