import { DashboardView } from '@/components/dashboard/DashboardView';

export default function ExecutiveDashboardPage() {
  return (
    <DashboardView
      title="Executive Dashboard"
      subtitle="Organization-wide security posture and risk overview"
      fetchKey="executive"
    />
  );
}
