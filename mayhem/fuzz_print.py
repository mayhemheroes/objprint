#! /usr/bin/env python3
import atheris
import io
import sys
import fuzz_helpers
from contextlib import contextmanager

with atheris.instrument_imports(include=["objprint"]):
    import objprint

@contextmanager
def nostdout():
    save_stdout = sys.stdout
    save_stderr = sys.stderr
    sys.stdout = io.BytesIO()
    sys.stderr = io.BytesIO()
    yield
    sys.stdout = save_stdout
    sys.stderr = save_stderr

def get_random_obj(fdp: fuzz_helpers.EnhancedFuzzedDataProvider) -> object:
    try:
        attributes = {}
        for _ in range(fdp.ConsumeIntInRange(0, 10)):
            attr_name = fdp.ConsumeRandomString()
            attr_ty = fdp.ConsumeIntInRange(0, 4)

            if attr_ty == 0:
                attributes[attr_name] = fuzz_helpers.build_fuzz_list(fdp, [int])
            elif attr_ty == 1:
                attributes[attr_name] = fuzz_helpers.build_fuzz_set(fdp, [tuple, str])
            elif attr_ty == 2:
                attributes[attr_name] = get_random_obj(fdp)
            elif attr_ty == 3:
                attributes[attr_name] = fuzz_helpers.build_fuzz_dict(fdp, [float, list, str])
            elif attr_ty == 4:
                attributes[attr_name] = fuzz_helpers.build_fuzz_tuple(fdp, [list, bool])

        return type(fdp.ConsumeRandomString(), (object,), attributes)()
    except Exception:
        return None


def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)

    try:
        with nostdout():
            choice = fdp.ConsumeIntInRange(0, 5)

            rand_obj = get_random_obj(fdp)
            if choice == 0:
                objprint.op(rand_obj, print_methods=fdp.ConsumeBool(), line_number=fdp.ConsumeBool())
            elif choice == 1:
                objprint.objstr(rand_obj)
            elif choice == 2:
                objprint.objjson(rand_obj)
            elif choice == 3:
                objprint.op(rand_obj, attr_pattern=fdp.ConsumeRandomString())
            elif choice == 4:
                objprint.op(rand_obj, include=fuzz_helpers.build_fuzz_list(fdp, [str]))
            elif choice == 5:
                objprint.op(rand_obj, exclude=fuzz_helpers.build_fuzz_list(fdp, [str]))
    except TypeError as e:
        if 'bytes-like' in str(e):
            return -1
        raise e


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
