
# Module: <code>anynet.queue</code>

Provides a simple queue.

<code>**def create**(size: int = math.inf) -> [Queue](#queue)</code><br>
<span class="docs">Creates a queue. If the queue is wrapped in an `async with` statement it is closed automatically.</span>

## Queue
<code>**async def put**(value: object) -> None</code><br>
<span class="docs">Adds an item to the queue. Blocks if the queue is full.</span>

<code>**async def get**() -> object</code><br>
<span class="docs">Gets an item from the queue. Blocks if the queue is empty.</span>

<code>**async def close**() -> None</code><br>
<span class="docs">Closes the queue.</span>
