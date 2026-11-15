from datetime import datetime, timezone

import pytest
import stix2

from app.feeds import stix_records
from app.intelligence import record_metadata


def test_stix_restricted_marking_is_preserved():
    obj={'type':'indicator','id':'indicator--controlled','pattern':"[domain-name:value = 'example.org']",'object_marking_refs':[stix2.TLP_RED.id,stix2.TLP_GREEN.id]}
    assert list(stix_records([obj]))[0]['tlp']=='red'
    obj['object_marking_refs']=['marking-definition--unknown']
    with pytest.raises(ValueError,match='Unknown STIX handling'):
        list(stix_records([obj]))


def test_record_metadata_validates_timestamp_and_tlp():
    marking,timestamp=record_metadata({'tlp':'AMBER','last_seen':'2026-07-01T12:00:00Z'})
    assert marking=='amber' and timestamp==datetime(2026,7,1,12,tzinfo=timezone.utc)
    with pytest.raises(ValueError):record_metadata({'tlp':'unrestricted'})
    with pytest.raises(ValueError):record_metadata({'last_seen':'2026-07-01T12:00:00'})
