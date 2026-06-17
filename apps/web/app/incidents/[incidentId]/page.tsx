import { IncidentDetailPage } from "../../../components/incidents/incident-detail-page";

export default async function IncidentPage({
  params
}: {
  params: Promise<{ incidentId: string }>;
}) {
  const { incidentId } = await params;
  return <IncidentDetailPage incidentId={incidentId} />;
}
