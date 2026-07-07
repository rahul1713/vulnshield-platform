'use client';

import { Button, Chip, Alert } from '@mui/material';
import { Add } from '@mui/icons-material';
import { useQuery } from '@tanstack/react-query';
import { assetsApi } from '@/lib/api';
import { useToast } from '@/components/ui/ToastProvider';
import { PageHeader } from '@/components/ui/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { Asset } from '@/types';
import { useState } from 'react';

const columns: Column<Asset>[] = [
  { id: 'name', label: 'Name', sortable: true },
  { id: 'asset_type', label: 'Type', sortable: true, render: (row) => row.asset_type.replace(/_/g, ' ') },
  { id: 'ip_address', label: 'IP Address', getValue: (row) => row.ip_address || '—' },
  { id: 'hostname', label: 'Hostname', getValue: (row) => row.hostname || '—' },
  { id: 'os_family', label: 'OS', getValue: (row) => row.os_version ? `${row.os_family} ${row.os_version}` : row.os_family || '—' },
  {
    id: 'criticality',
    label: 'Criticality',
    sortable: true,
    render: (row) => (
      <Chip label={row.criticality} size="small" color={row.criticality >= 4 ? 'error' : row.criticality >= 3 ? 'warning' : 'default'} />
    ),
  },
  {
    id: 'status',
    label: 'Status',
    render: (row) => <Chip label={row.status.replace(/_/g, ' ')} size="small" variant="outlined" />,
  },
  { id: 'vulnerability_count', label: 'Vulns', sortable: true, getValue: (row) => row.vulnerability_count ?? 0 },
  { id: 'risk_score', label: 'Risk', sortable: true, getValue: (row) => row.risk_score?.toFixed(1) ?? '—' },
];

export default function AssetsPage() {
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [search, setSearch] = useState('');
  const { showToast } = useToast();

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['assets', page, pageSize, search],
    queryFn: () => assetsApi.list({ page: page + 1, page_size: pageSize, search }),
  });

  return (
    <>
      <PageHeader
        title="Assets"
        subtitle="Manage and monitor your infrastructure inventory"
        action={
          <Button
            variant="contained"
            startIcon={<Add />}
            onClick={() =>
              showToast('Asset creation requires the asset-service API. Run `make up` to start the full stack.', 'info')
            }
          >
            Add Asset
          </Button>
        }
      />
      {isError && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error instanceof Error ? error.message : 'Failed to load assets'}
        </Alert>
      )}
      <DataTable
        columns={columns}
        data={data?.items ?? []}
        total={data?.total ?? 0}
        loading={isLoading}
        page={page}
        pageSize={pageSize}
        onPageChange={setPage}
        onPageSizeChange={(size) => { setPageSize(size); setPage(0); }}
        onSearchChange={(q) => { setSearch(q); setPage(0); }}
        searchPlaceholder="Search assets..."
        filters={[
          { id: 'status', label: 'All Statuses', options: [
            { value: 'active', label: 'Active' },
            { value: 'inactive', label: 'Inactive' },
          ]},
        ]}
        getRowId={(row) => row.id}
      />
    </>
  );
}
