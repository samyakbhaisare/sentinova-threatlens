import type { Metadata } from 'next';
import './style.css';
import 'leaflet/dist/leaflet.css';

export const metadata: Metadata = {title:'Sentinova ThreatLens | Security Operations', description:'Threat intelligence and SOC operations workspace'};
export default function Layout({children}:{children:React.ReactNode}) {
  return <html lang="en"><body>{children}</body></html>;
}
