#!/bin/bash


echo Please input the domain you would like to scan:
read domain

subdomainEnum(){
	mkdir -p $domain $domain/subs $domain/recon
	subfinder -d $domain -o $domain/subs/SubfinderResults.txt
	assetfinder -subs-only  $domain | tee $domain/subs/assetFinderResults.txt
	cat $domain/subs/*.txt | tee $domain/subs/allSubsFound.txt
	uniq $domain/subs/allSubsFound.txt
}
subdomainEnum

subdomainValidation(){
	cat $domain/subs/allSubsFound.txt |httprobe | tee $domain/subs/Httprobe.txt
	python3 EyeWitness.py --web -f $domain/subs/Httprobe.txt 
}
subdomainValidation

nucleiScan(){
	nuclei -l $domain/subs/Httprobe.txt -t cves -t vulnerabilities -o $domain/recon/Nuclei.txt
}
nucleiScan

spidering(){
	cat $domain/subs/Httprobe.txt | waybackurls |tee $domain/recon/spider.txt
	cat $domain/recon/spider.txt | gf xss | tee $domain/recon/xss.txt
	cat $domain/recon/spider.txt | gf sqli | tee $domain/recon/sqli.txt
	cat $domain/recon/spider.txt | gf img-traversal |tee $domain/recon/traversal.txt
	cat $domain/recon/spider.txt | grep "\.apk" | tee $domain/recon/APK.txt
	cat $domain/recon/spider.txt | grep "\.js"| tee $domain/recon/JavaScript.txt
}
spidering

XSS+DisclosureScan(){
	cat $domain/recon/xss.txt | dalfox pipe --mass | tee $domain/recon/DalfoxScan.txt
	cat $domain/recon/JavaScript.txt ||xargs -I %% bash -c 'python3 SecretFinder.py -i %% -o $domain/recon/SecretFinder.html'
}

