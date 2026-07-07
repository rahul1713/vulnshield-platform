'use client';

import {
  Box,
  Card,
  CardContent,
  IconButton,
  InputAdornment,
  MenuItem,
  Select,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TablePagination,
  TableRow,
  TableSortLabel,
  TextField,
  Typography,
} from '@mui/material';
import { FilterList, Search } from '@mui/icons-material';
import { useMemo, useState } from 'react';

export interface Column<T> {
  id: string;
  label: string;
  sortable?: boolean;
  width?: string | number;
  render?: (row: T) => React.ReactNode;
  getValue?: (row: T) => string | number | undefined;
}

interface FilterOption {
  id: string;
  label: string;
  options: { value: string; label: string }[];
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  total?: number;
  loading?: boolean;
  page?: number;
  pageSize?: number;
  onPageChange?: (page: number) => void;
  onPageSizeChange?: (size: number) => void;
  onSortChange?: (field: string, order: 'asc' | 'desc') => void;
  onRowClick?: (row: T) => void;
  rowActions?: (row: T) => React.ReactNode;
  searchPlaceholder?: string;
  onSearchChange?: (query: string) => void;
  filters?: FilterOption[];
  onFilterChange?: (filterId: string, value: string) => void;
  getRowId: (row: T) => string;
  emptyMessage?: string;
}

export function DataTable<T>({
  columns,
  data,
  total,
  loading = false,
  page = 0,
  pageSize = 10,
  onPageChange,
  onPageSizeChange,
  onSortChange,
  onRowClick,
  rowActions,
  searchPlaceholder = 'Search...',
  onSearchChange,
  filters,
  onFilterChange,
  getRowId,
  emptyMessage = 'No data found',
}: DataTableProps<T>) {
  const [sortField, setSortField] = useState<string>('');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');
  const [search, setSearch] = useState('');
  const [filterValues, setFilterValues] = useState<Record<string, string>>({});

  const handleSort = (field: string) => {
    const isAsc = sortField === field && sortOrder === 'asc';
    const newOrder = isAsc ? 'desc' : 'asc';
    setSortField(field);
    setSortOrder(newOrder);
    onSortChange?.(field, newOrder);
  };

  const handleSearch = (value: string) => {
    setSearch(value);
    onSearchChange?.(value);
  };

  const handleFilter = (filterId: string, value: string) => {
    setFilterValues((prev) => ({ ...prev, [filterId]: value }));
    onFilterChange?.(filterId, value);
  };

  const displayTotal = total ?? data.length;

  const skeletonRows = useMemo(() => Array.from({ length: 5 }), []);

  return (
    <Card>
      <CardContent sx={{ p: 0, '&:last-child': { pb: 0 } }}>
        <Box sx={{ p: 2, display: 'flex', flexWrap: 'wrap', gap: 2, alignItems: 'center' }}>
          <TextField
            size="small"
            placeholder={searchPlaceholder}
            value={search}
            onChange={(e) => handleSearch(e.target.value)}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <Search fontSize="small" />
                </InputAdornment>
              ),
            }}
            sx={{ minWidth: 240, flexGrow: 1, maxWidth: 400 }}
          />
          {filters?.map((filter) => (
            <Select
              key={filter.id}
              size="small"
              displayEmpty
              value={filterValues[filter.id] || ''}
              onChange={(e) => handleFilter(filter.id, e.target.value)}
              sx={{ minWidth: 140 }}
            >
              <MenuItem value="">{filter.label}</MenuItem>
              {filter.options.map((opt) => (
                <MenuItem key={opt.value} value={opt.value}>
                  {opt.label}
                </MenuItem>
              ))}
            </Select>
          ))}
          <IconButton size="small">
            <FilterList />
          </IconButton>
        </Box>

        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                {columns.map((col) => (
                  <TableCell key={col.id} width={col.width}>
                    {col.sortable && onSortChange ? (
                      <TableSortLabel
                        active={sortField === col.id}
                        direction={sortField === col.id ? sortOrder : 'asc'}
                        onClick={() => handleSort(col.id)}
                      >
                        {col.label}
                      </TableSortLabel>
                    ) : (
                      col.label
                    )}
                  </TableCell>
                ))}
                {rowActions && <TableCell align="right">Actions</TableCell>}
              </TableRow>
            </TableHead>
            <TableBody>
              {loading
                ? skeletonRows.map((_, i) => (
                    <TableRow key={i}>
                      {columns.map((col) => (
                        <TableCell key={col.id}>
                          <Skeleton />
                        </TableCell>
                      ))}
                    </TableRow>
                  ))
                : data.length === 0
                  ? (
                    <TableRow>
                      <TableCell colSpan={columns.length + (rowActions ? 1 : 0)} align="center" sx={{ py: 4 }}>
                        <Typography color="text.secondary">{emptyMessage}</Typography>
                      </TableCell>
                    </TableRow>
                  )
                  : data.map((row) => (
                    <TableRow
                      key={getRowId(row)}
                      hover
                      onClick={() => onRowClick?.(row)}
                      sx={{ cursor: onRowClick ? 'pointer' : 'default' }}
                    >
                      {columns.map((col) => (
                        <TableCell key={col.id}>
                          {col.render
                            ? col.render(row)
                            : col.getValue
                              ? col.getValue(row)
                              : (row as Record<string, unknown>)[col.id]?.toString()}
                        </TableCell>
                      ))}
                      {rowActions && (
                        <TableCell align="right" onClick={(e) => e.stopPropagation()}>
                          {rowActions(row)}
                        </TableCell>
                      )}
                    </TableRow>
                  ))}
            </TableBody>
          </Table>
        </TableContainer>

        <TablePagination
          component="div"
          count={displayTotal}
          page={page}
          rowsPerPage={pageSize}
          onPageChange={(_, newPage) => onPageChange?.(newPage)}
          onRowsPerPageChange={(e) => onPageSizeChange?.(parseInt(e.target.value, 10))}
          rowsPerPageOptions={[10, 25, 50, 100]}
        />
      </CardContent>
    </Card>
  );
}
