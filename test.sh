#!/bin/bash

i=1
for k in $( seq 1 1000 )
do
	./cpabe-all pub_key kevin_priv_key security_report.pdf.cpabe
done
