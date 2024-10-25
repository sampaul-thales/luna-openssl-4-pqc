#!/bin/bash

BUILD_CMD="$PWD/build.sh"

if [ ! -s "$BUILD_CMD" ]; then
    echo "Error! The build script $BUILD_CMD not found."
    exit 1
fi

function usage {
    echo
    echo "NAME"
    echo "   $0"
    echo
    echo "USAGE"
    echo "   $0 PRODUCT COMPONENT SCOPE"
    echo
    echo "   PRODUCT: SA64 | SA64client | DevTools"
    echo "   COMPONENT (TARGET): all, ..."
    echo "   SCOPE (optional): full | incremental (default)"
    echo "      full scan will clean up the existing scan files"
    echo
    echo "DESCRIPTION"
    echo "   This script performs Coverity scan of a source repository locally on a development machine."
    echo "   You must download the Coverity analysis tools from the Coverity server, install it,"
    echo "   add the bin directory to the PATH environment variable before running this script."
    exit
 }

# Get usage if asked for help
if [ "$1" == "?" ] || [ "$2" == "?" ] || [ "$3" == "?" ] ||
   [ "$1" == "help" ] || [ "$2" == "help" ] || [ "$3" == "help" ]; then
    usage
fi

# Product name
if [ "$1" == "SA64" ]; then
    PRODUCT="$1"
elif [ "$1" == "SA64client" ]; then
    PRODUCT="$1"
elif [ "$1" == "DevTools" ]; then
    PRODUCT="$1"
else
    # show help
    make PRODUCT="$PRODUCT"
    exit
fi

# Component
if [ -z "$2" ]; then
    echo "$0: missing component (target) argument"
    # show help
    make PRODUCT="$PRODUCT"
    exit
else
    COMPONENT="$2"
fi

# full / incremntal scan
if [ -z "$3" ]; then
    SCOPE="incremental"
elif [ "$3" == "full" ]; then
    SCOPE="$3"
elif [ "$3" == "incremental" ]; then
    SCOPE="$3"
else
    echo "Scope '$3' is not valid"
    exit
fi

if [ -z "$4" ]; then
    COV_DIR="$PWD/artifacts/$PRODUCT/coverity-data"
else
    COV_DIR="$1"
fi
HTML_DIR="$COV_DIR"/../coverity-results

START=$(date +%s)

DAILY_CHECKERS="--security --concurrency --enable-fnptr --enable-constraint-fpp \
        --enable INTEGER_OVERFLOW --checker-option INTEGER_OVERFLOW:enable_tainted_params:true \
        --enable-callgraph-metrics --allow-unmerged-emits"

EXTRA_CI_CHECKERS="--enable OVERFLOW_BEFORE_WIDEN --enable OVERRUN --enable DC.STRING_BUFFER --enable STACK_USE \
        --enable DC.STREAM_BUFFER --enable DC.WEAK_CRYPTO --aggressiveness-level medium"

CODING_STANDARD=
# Uncomment to scan for coding standard
#CODING_STANDARD="--coding-standard-config= /usr/local/cov-analysis-linux64-2022.6.0/config/coding-standards/misracpp2008/misracpp2008-all.config"

function prepare {
    cov-configure --compiler gcc --comptype gcc --template || exit 1

    if [  "$SCOPE" == "full" ]; then
        # clean
        "$BUILD_CMD" "$PRODUCT" clean "$COMPONENT" || exit 1
        rm -rf "$COV_DIR" || exit 1
    fi
    mkdir -p "$COV_DIR" || exit 1
    rm -f  summary.txt
}

function build {
    START=$(date +%s)
    # Use BLDTYPE=ci to skip signing the jar files which are very slow and not needed for Coverity analysis.
    cov-build --dir="$COV_DIR" bash "$BUILD_CMD" "$PRODUCT" build "$COMPONENT" "ci"
    rc=$?
    END_BUILD=$(date +%s)
    DIFF_BUILD=$((END_BUILD - START))
    if [ $rc -ne 0 ]; then
        echo "Failed to build $COMPONENT for $PRODUCT. Please fix the build errors and try again." | tee -a summary.txt
    else
        echo "Coverity build done in $DIFF_BUILD seconds."  | tee -a summary.txt
    fi
    return "$rc"
}

function analyze {
    START=$(date +%s)
    cov-analyze --dir="$COV_DIR" $DAILY_CHECKERS $EXTRA_CI_CHECKERS --strip-path "$PWD" --strip-path "$PWD"\.. \
        $CODING_STANDARD | tee  summary.txt
    rc="$?"
    END=$(date +%s)
    ANALYSIS_TIME=$((END - START))
    if [ "$rc" -ne 0 ]; then
        echo "Coverity analysis failed." | tee -a summary.txt
    else
        echo "Coverity analaysis done in $ANALYSIS_TIME seconds." | tee -a summary.txt
    fi
    return "$rc"
}


function format {
    START=$(date +%s)
    if [ -d "$HTML_DIR" ]; then
        rm -rf "${HTML_DIR}.1"
        mv -f "${HTML_DIR}" "${HTML_DIR}.1" # keep the previous results
        echo "The previous analysis reports saved to ${HTML_DIR}.1" | tee -a summary.txt
    fi
    mkdir -p "$HTML_DIR" || exit 1
    echo "Generating new HTML reports in: $HTML_DIR"
    cov-format-errors --dir "$COV_DIR" --html-output "$HTML_DIR"
    rc="$?"
    END=$(date +%s)
    FORMAT_TIME=$((END - START))
    if [ "$rc" -ne 0 ]; then
        echo "Failed to generate HTM reports." | tee -a summary.txt
    else
        echo "Coverity HTML format done in $FORMAT_TIME seconds." | tee -a summary.txt
        echo
        echo "Open $HTML_DIR/index.html with a web browser to see the analysis results." | tee -a summary.txt
        echo
    fi
    mv -f summary.txt "$HTML_DIR"
    return "$rc"
}

echo
prepare && \
    build && \
    analyze && \
    format && \
    echo "Scan completed for product: $PRODUCT, components: $COMPONENT, scope: $SCOPE"  | tee -a "$HTML_DIR"/summary.txt
echo
exit "$rc"

