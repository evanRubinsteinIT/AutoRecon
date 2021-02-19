#!/bin/bash


echo Please input the domain you would like to scan:
read domain

subdomainEnum(){
	mkdir -p $domain $domain/subs $domain/recon
	subfinder -d $domain -o $domain/subs/SubfinderResults.txt
	assetfinder -subs-only  $domain | tee $domain/subs/assetFinderResults.txt
	cat $domain/subs/*.txt > $domain/subs/allSubsFound.txt
	uniq allSubsFound.txt
}
subdomainEnum

subdomainValidation(){
	cat $domain/subs/allSubsFound.txt |httprobe > $domain/subs/Httprobe.txt
}
subdomainValidation

nucleiScan(){
	nuclei -l $domain/subs/Httprobe.txt -t /home/username/nuclei-templates -c 100 -o $domain/recon/Nuclei.txt
	cat $domain/recon/Nuclei.txt | grep high | tee high.txt
	cat $domain/recon/Nuclei.txt | grep medium | tee medium.txt
	cat $domain/recon/Nuclei.txt | grep low | tee low.txt
	cat $domain/recon/Nuclei.txt | grep critical | critical.txt

}
nucleiScan

spidering(){
	cat $domain/subs/Httprobe.txt | gospider |tee $domain/recon/spider.txt
	cat $domain/recon/spider.txt | gf xss | tee $domain/recon/xss.txt
	cat $domain/recon/spider.txt | gf sqli | tee $domain/recon/sqli.txt
	cat $domain/recon/spider.txt | gf idor | tee $domain/recon/idor.txt
	cat $domain/recon/spider.txt | gf img-traversal |tee $domain/recon/traversal.txt
	cat $domain/recon/spider.txt | gf interestingEXT |tee $domain/recon/interestingSubs.txt
	cat $domain/recon/spider.txt | gf interestingsubs |tee $domain/recon/interestingSubs.txt
	cat $domain/recon/spider.txt| gf rce | tee $domain/recon/rce.txt
	cat $domain/recon/spider.txt | gf debug_logic | tee $domain/recon/debug.txt
}
spidering
