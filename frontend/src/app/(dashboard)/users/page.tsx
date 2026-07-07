'use client';

import { Button, Chip } from '@mui/material';
import { PersonAdd } from '@mui/icons-material';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { usersApi } from '@/lib/api';
import { useToast } from '@/components/ui/ToastProvider';
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
  const { showToast } = useToast();

  const { data, isLoading } = useQuery({
    queryKey: ['users', page, pageSize],
    queryFn: () => usersApi.list({ page: page + 1, page_size: pageSize }),
  });

  return (
    <>
      <PageHeader
        title="Users"
        subtitle="Manage user accounts and role assignments"
        action={
          <Button
            variant="contained"
            startIcon={<PersonAdd />}
            onClick={() =>
              showToast('User provisioning requires the auth-service API. Run `make up` to start the full stack.', 'info')
            }
          >
            Add User
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
