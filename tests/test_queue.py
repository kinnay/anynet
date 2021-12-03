
from anynet import queue
import pytest

@pytest.mark.anyio
async def test_queue():
	async with queue.create() as q:
		await q.put(1)
		await q.put(2)
		assert await q.get() == 1
		assert await q.get() == 2
