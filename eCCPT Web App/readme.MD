## Information Gathering

We can use [Netcraft](https://sitereport.netcraft.com/) to generate site reports 


### Fingerprint Webapp

Fingerprint websites using...

-Netcat (cmd)

-httpprint

-wappalyzer (Extension)

-whatweb (cmd)

Generally, [Microsoft](https://learn.microsoft.com/en-us/lifecycle/products/internet-information-services-iis) IIS uses...

IS 8.5 on Windows Server 2012 R2	Nov 25, 2013	Oct 10, 2023

IIS 8.5 on Windows 8.1	Nov 13, 2013	Jan 10, 2023

IIS 8 on Windows Server 2012	Oct 30, 2012	Oct 10, 2023

IIS 7.5 on Windows 7*	Oct 22, 2009	Jan 14, 2020

IIS 7.5 on Windows Server 2008 R2*	Oct 22, 2009	Jan 14, 2020

IIS 7.0 on Windows Server 2008*	May 6, 2008	Jan 14, 2020

IIS 6.0 on Windows Server 2003	May 28, 2003	Jul 14, 2015

### Enumerating Subdomains

Google: site:<target domain>
  
dnsenum: `dns enum -p <pages to process> -s <limit results to 100 subdomains> --threads 5 <domain>
  
  
  

