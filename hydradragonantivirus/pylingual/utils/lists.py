def unflatten(flattened: list, reference: list[list]):
    for i, request in enumerate(reference):
        flattened[i : i + len(request)] = [flattened[i : i + len(request)]]


def flatten(x):
    for e in x:
        if isinstance(e, list):
            yield from flatten(e)
        else:
            yield e
