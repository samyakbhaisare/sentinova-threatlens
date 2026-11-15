'use client';
import {MapContainer,TileLayer,CircleMarker,Popup,useMap} from 'react-leaflet';
import {useEffect,useMemo,useState} from 'react';

export type GeoPoint={latitude:number;longitude:number;country:string;provider:string;direction:string;indicator_id?:string;event_id?:string;controlled_test?:boolean};
function RegionFocus({points,region}:{points:GeoPoint[];region:string}) {
 const map=useMap();
 useEffect(()=>{if(region&&points.length)map.fitBounds(points.map(p=>[p.latitude,p.longitude] as [number,number]),{maxZoom:6,padding:[20,20]});else map.setView([20,0],2);},[map,points,region]);
 return null;
}
export default function Heatmap({points}:{points:GeoPoint[]}) {
  const [region,setRegion]=useState(''),[direction,setDirection]=useState('');
  const visible=useMemo(()=>points.filter(p=>(!region||p.country===region)&&(!direction||p.direction===direction)),[points,region,direction]);
  const buckets=new Map<string, {point:GeoPoint;count:number}>();
  for(const point of visible){const key=`${point.direction}:${point.latitude.toFixed(1)},${point.longitude.toFixed(1)}`;const old=buckets.get(key);buckets.set(key,{point,count:(old?.count||0)+1});}
  return <><div className="toolbar"><label>Activity direction<select value={direction} onChange={e=>setDirection(e.target.value)}><option value="">Origins and targets</option><option value="origin">Origins</option><option value="target">Targets</option></select></label><label>Region drilldown<select value={region} onChange={e=>setRegion(e.target.value)}><option value="">All regions</option>{[...new Set(points.map(p=>p.country).filter(Boolean))].sort().map(country=><option key={country}>{country}</option>)}</select></label></div><MapContainer center={[20,0]} zoom={2} scrollWheelZoom={false} style={{height:320,width:'100%'}} aria-label="Threat origin and target geographic density">
    <RegionFocus points={visible} region={region}/>
    <TileLayer attribution='&copy; OpenStreetMap contributors' url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"/>
    {[...buckets.entries()].map(([key,{point,count}])=><CircleMarker key={key} center={[point.latitude,point.longitude]} radius={Math.min(35,8+Math.log2(count+1)*5)} pathOptions={{color:point.direction==='target'?'#53dfca':'#f97366',fillColor:point.direction==='target'?'#16a085':'#ef4444',fillOpacity:Math.min(.8,.2+count*.03),weight:1}}><Popup>{point.country}: {count} {point.direction==='target'?'correlated events':'indicators'}<br/>{point.direction} • {point.provider}{point.controlled_test?' • controlled test':''}</Popup></CircleMarker>)}
  </MapContainer>{!visible.length&&<p className="muted">No geolocation evidence for these filters. Origins require enabled enrichment; targets require source-attributed telemetry and an IOC match.</p>}<details><summary>Accessible geographic observations</summary><table><thead><tr><th>Direction</th><th>Country</th><th>Count</th><th>Source</th></tr></thead><tbody>{[...buckets.entries()].map(([key,{point,count}])=><tr key={key}><td>{point.direction}</td><td>{point.country}</td><td>{count}</td><td>{point.provider}</td></tr>)}</tbody></table></details><p className="muted">Source-reported infrastructure locations; location does not establish attacker identity. Basemap requests go to OpenStreetMap.</p></>;
}
