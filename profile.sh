if [ $# -gt 0 ]; then
	ptype=$1
else
	ptype=text
fi

LD_PRELOAD=/usr/lib/libprofiler.so.0 CPUPROFILE=/tmp/test.prof \
	./parse
google-pprof --"$ptype" ./parse /tmp/test.prof
