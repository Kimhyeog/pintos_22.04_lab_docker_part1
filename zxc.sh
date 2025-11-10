# 결과 확인
if [ -f "$TEST" ]; then
    if grep -q "FAIL" "$TEST"; then
        echo "========================================"
        echo "TEST: $TEST"
        echo "---------- RESULT ----------"
        cat "$TEST"

        # .output와 .errors 경로 계산
        OUTPUT="${TEST%.result}.output"
        ERRORS="${TEST%.result}.errors"

        if [ -f "$OUTPUT" ]; then
            echo "---------- OUTPUT ----------"
            cat "$OUTPUT"
        else
            echo "No output file found."
        fi

        if [ -f "$ERRORS" ]; then
            echo "---------- ERRORS ----------"
            cat "$ERRORS"
        else
            echo "No errors file found."
        fi
    else
        echo "$TEST PASSED ✅"
    fi
else
    echo "Result file $TEST not found. Did the test actually run?"
fi
