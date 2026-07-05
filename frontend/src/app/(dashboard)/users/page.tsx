'use client';

import { Button, Chip } from '@mui/material';
import { PersonAdd } from '@mui/icons-material';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { usersApi } from '@/lib/api';
import { MOCK_USERS, paginate } from '@/lib/mock-data';
import { PageHeader } from '@/components/ui/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { ProtectedRoute } from '@/components/layout/ProtectedRoute';
import { User } from '@/types';

const columns: Column<User>[] = [
  { id: 'username', label: 'Username', sortable: true },
  { id: 'email', label: 'Email' },
  {
    id: 'name',
    label: 'Name',
    getValue: (row) => `${row.first_name || ''} ${row.last_name || ''}`.trim() || '—',
  },
  {
    id: 'role',
    label: 'Role',
    render: (row) => <Chip label={row.role.replace(/_/g, ' ')} size="small" variant="outlined" sx={{ textTransform: 'capitalize' }} />,
  },
  {
    id: 'is_active',
    label: 'Status',
    render: (row) => <Chip label={row.is_active ? 'Active' : 'Inactive'} size="small" color={row.is_active ? 'success' : 'default'} />,
  },
  { id: 'last_login', label: 'Last Login', getValue: (row) => row.last_login ? new Date(row.last_login).toLocaleString() : '—' },
];

function UsersContent() {
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);

  const { data, isLoading } = useQuery({
    queryKey: ['users', page, pageSize],
    queryFn: async () => {
      try {
        return await usersApi.list({ page: page + 1, page_size: pageSize });
      } catch {
        return paginate(MOCK_USERS, page + 1, pageSize);
      }
    },
  });

  return (
    <>
      <PageHeader
        title="Users"
        subtitle="Manage user accounts and role assignments"
        action={<Button variant="contained" startIcon={<PersonAdd />}>Add User</Button>}
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
        searchPlaceholder="Search users..."
        getRowId={(row) => row.id}
      />
    </>
  );
}

export default function UsersPage() {
  return (
    <ProtectedRoute permissions={['users:read']}>
      <UsersContent />
    </ProtectedRoute>
  );
}
