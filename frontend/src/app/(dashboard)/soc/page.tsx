import { DashboardView } from '@/components/dashboard/DashboardView';

export default function SocDashboardPage() {
  return (
    <DashboardView
      title="SOC Dashboard"
      subtitle="Real-time security operations center metrics and alerts"
      fetchKey="soc"
    />
  );
}
