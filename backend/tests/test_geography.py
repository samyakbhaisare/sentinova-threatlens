from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.geography import target_points
from app.schemas import EventCreate, Observable


def event_payload():
    return {'source':'controlled-siem','external_id':'one','occurred_at':'2026-10-28T00:00:00Z','asset':'controlled-host',
        'observables':[{'type':'ip','value':'192.0.2.1'}], 'controlled_test':True,
        'details':{'target_geo':{'latitude':0.0,'longitude':0.0,'country':'ZZ','source':'controlled IPAM fixture','observed_at':'2026-10-28T00:00:00Z'}}}


def test_target_evidence_preserves_zero_coordinates_provenance_and_deduplicates():
    payload=EventCreate.model_validate(event_payload())
    event=SimpleNamespace(id='controlled',asset=payload.asset,details=payload.details,controlled_test=True)
    result=target_points([event,event])
    assert len(result)==1 and result[0]['latitude']==0 and result[0]['longitude']==0
    assert result[0]['provider']=='controlled IPAM fixture' and result[0]['controlled_test'] is True


@pytest.mark.parametrize('field,value',[('latitude',91),('longitude',-181),('source',''),('country','ZZZ'),('observed_at','2026-10-28T00:00:00')])
def test_target_geography_requires_valid_source_observation(field,value):
    payload=event_payload();payload['details']['target_geo'][field]=value
    with pytest.raises(ValidationError):EventCreate.model_validate(payload)


def test_invalid_legacy_geo_and_nonfinite_details_fail_safely():
    assert target_points([SimpleNamespace(id='old',details={'target_geo':{'latitude':1}})])==[]
    payload=event_payload();payload['details']['invalid']=float('nan')
    with pytest.raises(ValidationError):EventCreate.model_validate(payload)
    with pytest.raises(ValidationError):Observable(type='not-an-ioc',value='example.org')
