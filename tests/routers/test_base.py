import pytest
from routers.base import BaseRouter

def test_base_router_cannot_be_instantiated():
    with pytest.raises(TypeError):
        BaseRouter() # type: ignore

def test_concrete_router_implementation():
    class TestRouter(BaseRouter):
        def get_device_data(self):
            return [{"ip": "1.1.1.1"}]
    
    router = TestRouter()
    assert router.get_device_data() == [{"ip": "1.1.1.1"}]
