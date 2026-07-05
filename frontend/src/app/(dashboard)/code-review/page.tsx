'use client';

import { Button } from '@mui/material';
import { Code } from '@mui/icons-material';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { codeReviewApi } from '@/lib/api';
import { MOCK_CODE_REVIEWS, paginate } from '@/lib/mock-data';
import { PageHeader } from '@/components/ui/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { StatusChip } from '@/components/ui/SeverityChip';
import { CodeReview } from '@/types';

const columns: Column<CodeReview>[] = [
  { id: 'repository_url', label: 'Repository', getValue: (row) => row.repository_url?.replace('https://github.com/', '') || '—' },
  { id: 'branch', label: 'Branch' },
  { id: 'language', label: 'Language', getValue: (row) => row.language || '—' },
  { id: 'status', label: 'Status', render: (row) => <StatusChip status={row.status} /> },
  { id: 'findings_count', label: 'Findings', sortable: true },
  { id: 'started_at', label: 'Started', getValue: (row) => row.started_at ? new Date(row.started_at).toLocaleString() : '—' },
  { id: 'completed_at', label: 'Completed', getValue: (row) => row.completed_at ? new Date(row.completed_at).toLocaleString() : '—' },
];

export default function CodeReviewPage() {
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);

  const { data, isLoading } = useQuery({
    queryKey: ['code-review', page, pageSize],
    queryFn: async () => {
      try {
        return await codeReviewApi.list({ page: page + 1, page_size: pageSize });
      } catch {
        return paginate(MOCK_CODE_REVIEWS, page + 1, pageSize);
      }
    },
  });

  return (
    <>
      <PageHeader
        title="AI Code Review"
        subtitle="Automated security analysis of source code repositories"
        action={<Button variant="contained" startIcon={<Code />}>New Review</Button>}
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
        searchPlaceholder="Search reviews..."
        getRowId={(row) => row.id}
      />
    </>
  );
}
