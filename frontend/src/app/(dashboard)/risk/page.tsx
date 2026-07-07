'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { riskApi } from '@/lib/api';
import { PageHeader } from '@/components/ui/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { RiskScore } from '@/types';

const columns: Column<RiskScore>[] = [
  { id: 'entity_name', label: 'Entity', sortable: true, getValue: (row) => row.entity_name || row.entity_id },
  { id: 'entity_type', label: 'Type', render: (row) => row.entity_type.replace(/_/g, ' ') },
  { id: 'technical_risk', label: 'Technical', getValue: (row) => row.technical_risk?.toFixed(1) ?? '—' },
  { id: 'business_risk', label: 'Business', getValue: (row) => row.business_risk?.toFixed(1) ?? '—' },
  {
    id: 'overall_score',
    label: 'Overall',
    sortable: true,
    render: (row) => (
      <span style={{ color: (row.overall_score ?? 0) >= 80 ? '#ef4444' : (row.overall_score ?? 0) >= 60 ? '#f97316' : '#22c55e', fontWeight: 600 }}>
        {row.overall_score?.toFixed(1) ?? '—'}
      </span>
    ),
  },
  { id: 'calculated_at', label: 'Calculated', getValue: (row) => new Date(row.calculated_at).toLocaleString() },
];

export default function RiskPage() {
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);

  const { data, isLoading } = useQuery({
    queryKey: ['risk', page, pageSize],
    queryFn: () => riskApi.list({ page: page + 1, page_size: pageSize }),
  });

  return (
    <>
      <PageHeader title="Risk" subtitle="Technical and business risk scores across assets and vulnerabilities" />
      <DataTable
        columns={columns}
        data={data?.items ?? []}
        total={data?.total ?? 0}
        loading={isLoading}
        page={page}
        pageSize={pageSize}
        onPageChange={setPage}
        onPageSizeChange={setPageSize}
        searchPlaceholder="Search risk scores..."
        getRowId={(row) => row.id}
      />
    </>
  );
}
