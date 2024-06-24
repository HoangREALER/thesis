#! /bin/bash

python3 webFuzz.py  http://localhost:8001 \
        -p -s \
	-m ../../demo_web/task_assignment_instrumented/instr.meta \
        -t sqli \
        -b 'sqli/$|id||*'\
        --driver_file /snap/bin/geckodriver \
        -vv
