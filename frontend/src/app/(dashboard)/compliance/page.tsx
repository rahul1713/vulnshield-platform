'use client';

import { LinearProgress, Box } from '@mui/material';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { complianceApi } from '@/lib/api';
import { MOCK_COMPLIANCE, paginate } from '@/lib/mock-data';
import { PageHeader } from '@/components/ui/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { ComplianceAssessment } from '@/types';

const columns: Column<ComplianceAssessment>[] = [
  { id: 'framework_name', label: 'Framework', sortable: true, getValue: (row) => row.framework_name || '—' },
  {
    id: 'score',
    label: 'Score',
    sortable: true,
    render: (row) => (
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, minWidth: 120 }}>
        <LinearProgress
          variant="determinate"
          value={row.score ?? 0}
          sx={{ flexGrow: 1, height: 8, borderRadius: 4 }}
          color={row.score && row.score >= 80 ? 'success' : row.score && row.score >= 60 ? 'warning' : 'error'}
        />
        <span>{row.score?.toFixed(0)}%</span>
      </Box>
    ),
  },
  { id: 'passed_controls', label: 'Passed', getValue: (row) => row.passed_controls },
  { id: 'failed_controls', label: 'Failed', getValue: (row) => row.failed_controls },
  { id: 'total_controls', label: 'Total', getValue: (row) => row.total_controls },
  { id: 'assessed_at', label: 'Assessed', getValue: (row) => new Date(row.assessed_at).toLocaleDateString() },
];

export default function CompliancePage() {
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);

  const { data, isLoading } = useQuery({
    queryKey: ['compliance', page, pageSize],
    queryFn: async () => {
      try {
        return await complianceApi.listAssessments({ page: page + 1, page_size: pageSize });
      } catch {
        return paginate(MOCK_COMPLIANCE, page + 1, pageSize);
      }
    },
  });

  return (
    <>
      <PageHeader title="Compliance" subtitle="Framework assessments and control compliance status" />
      <DataTable
        columns={columns}
        data={data?.items ?? []}
        total={data?.total ?? 0}
        loading={isLoading}
        page={page}
        pageSize={pageSize}
        onPageChange={setPage}
        onPageSizeChange={setPageSize}
        searchPlaceholder="Search frameworks..."
        getRowId={(row) => row.id}
      />
    </>
  );
}
