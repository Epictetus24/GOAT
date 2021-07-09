package reporting

//Vuln stores details about the vuln
type Vuln struct {
	vulnid           int
	Name             string
	Riskrating       int
	Finding          string
	Summary          string
	Technicaldetails string
	Recommendation   string
	Owaspid          string
	CVE              string
	Cvssvector       string
	References       string
}

/* risk ratings are as follows
0 = info
1 = low
2 = medium
3 = high
4 = critical
*/

//Vulncollect stores a slice of the vulns captured.
type Vulncollect struct {
	Vulnlist      []Vuln
	Affectedhosts []string
}

//HSecfindings is the one liner for header security.
var Hsecfindings = []string{
	"The Strict-Transport-Security Header was missing from the applications HTTP responses",
	"The Content-Security-Policy was missing from the applications HTTP responses",
	"The application was missing the X-Frame-Options header and is potentially vulnerable to Cross-Frame Scripting",
	"The X-Content-Type-Options Header was missing from the applications HTTP responses",
	"The Referrer-Policy Header was missing from the applications HTTP responses",
	"The Permissions-Policy Header was missing from the applications HTTP responses ",
	"The X-XSS-Protection Header was missing from the applications HTTP responses",
}

//HSecsummaries is the recommendation for header security.
var Hsecsummaries = []string{
	"The Strict-Transport-Security Header was missing from the applications HTTP responses",
	"The \"Content-Security-Policy\" header is designed to modify the way browsers render pages, and thus to protect from various cross-site injections, including Cross-Site Scripting. It is important to set the header value correctly, in a way that will not prevent proper operation of the web site. For example, if the header is set to prevent execution of inline JavaScript, the web site must not use inline JavaScript in it's pages.",
	"Cross Site Framing is a vulnerability in the way the application renders itself within an iFrame. An attacker controlling a parent frame could capture keystrokes within a child frame. It is, therefore, imperative to the application, namely the initial authentication form, not be rendered inside an iFrame.",
	"The \"X-Content-Type-Options\" header (with \"nosniff\" value) prevents IE and Chrome from ignoring the content-type of a response. This action may prevent untrusted content (e.g. user uploaded content) from being executed on the user browser (after a malicious naming, for example).",
	`The "Referrer-Policy" HTTP response header instructs the browser when to send a referrer header along with user requests.
	Referrer headers are sent as a user navigates around the application or when they click a link to a 3rd party application. 
	Properly set, this response header helps browsers better protect users against information leakage and tracking.
	`,
	`The "Permissions-Policy" HTTP response header allows developers to selectively enable and disable use of various browser features and APIs.
	This can be used to disable browser features which are not needed and avoid any injected code being able to access these features.
	This header can be especially useful to restrict access for embedded sites in your webpages, for example by disabling geolocation, camera, microphone and notifications. 
	`,
	"The \"X-XSS-Protection\" header forces the Cross-Site Scripting filter into Enable mode, even if disabled by the user. This filter is built into most recent web browsers (IE 8+, Chrome 4+), and is usually enabled by default. Although it is not designed as first and only defence against Cross-Site Scripting, it acts as an additional layer of protection.",
}

//HSecrecommendations is the recommendation for header security.
var Hsecrecommendations = []string{
	" YOURCOMPANY Recommend that the application return the Strict-Transport-Security Header",
	` YOURCOMPANY recommends that the server be configured to send the \"Content-Security-Policy\" header.
	For Apache, see: http://httpd.apache.org/docs/2.2/mod/mod_headers.html 
	For nginx, see: http://nginx.org/en/docs/http/ngx_http_headers_module.html 
	For IIS, see: https://technet.microsoft.com/pl-pl/library/cc753133%28v=ws.10%29.aspx 
	HTTP Response Headers can be edited via the GUI in IIS Manager or add the following to your web.config, it allows everything but only from the same origin:
	<system.webServer>
	 <httpProtocol>
	 <customHeaders>
	 <add name=\"Content-Security-Policy\" value=\"default-src 'self';\" />
	 </customHeaders>
	 </httpProtocol>
	</system.webServer>
	`,
	` YOURCOMPANY recommends that the sites return a response header with the name X-Frame-Options and the value DENY to prevent framing altogether, or the value SAMEORIGIN to allow framing only by pages on the same origin as the response itself. In addition,  YOURCOMPANY also recommends that frame-busting code be employed within all the hosted applications.
	Frame busting is a method for ensuring that a website is not loaded within an iframe. This is usually performed with JavaScript similar to:
	if (top !=self) (top.location = self.location;)
	This however, can be defeated in some browsers, so the current best practice is to use the following suggested code:
	<style>html { display:none }</style>
	<script>
	if (self == top) {
	document.documentElement.style.display = 'block';
	} else {
	top.location = self.location;
	}
	</script>
	If the HTML style sheet option is not appropriate for the application, the following alternative code can be applied:
	Firstly, apply the following style element:
	<style id="antiClickjack">body{display:none !important;}</style>
	And then delete the style element through the following script.
	<script type="text/javascript">
	if (self === top) {
	var antiClickjack = document.getElementById("antiClickjack");
	antiClickjack.parentNode.removeChild(antiClickjack);
	} else {
	top.location = self.location;
	}
	</script>
	`,
	` YOURCOMPANY recommends that the server is configured to send the \"X-Content-Type-Options\" header with value \"nosniff\" on all outgoing requests.
	For Apache, see: http://httpd.apache.org/docs/2.2/mod/mod_headers.html 
	For IIS, see: https://technet.microsoft.com/pl-pl/library/cc753133%28v=ws.10%29.aspx 
	For nginx, see: http://nginx.org/en/docs/http/ngx_http_headers_module.html 
	`,
	` YOURCOMPANY recommends appropriately setting the "Referrer-Policy" HTTP response header for all server responses.
	If referrer headers are not specifically needed by the application when visiting other sites, "Referrer-Policy: no-referrer" can be used to effectively disable them in user's browsers.
	If referrer headers are needed by the application, they can be configured more securely with "Referrer-Policy: no-referrer-when-downgrade" to avoid disclosing the full URL path when a connection is downgraded to HTTP from HTTPS. Other options may also be considered to match your specific circumstances.
	`,
	` YOURCOMPANY recommends appropriately setting the "Permissions-Policy" HTTP response header for all server responses.
	Disable all browser features which your site does not make use of to minimise your user's exposure. 
	If embedding external content in your application, determine which browser features this embedded content requires access to and implement a whitelisting approach to allow appropriate access.
	`,
	` YOURCOMPANY recommends that the server is configured to send the \"X-XSS-Protection\" header with value \"1\" (i.e. Enabled) on all outgoing requests.
	For Apache, see: http://httpd.apache.org/docs/2.2/mod/mod_headers.html 
	For IIS, see: https://technet.microsoft.com/pl-pl/library/cc753133%28v=ws.10%29.aspx 
	For nginx, see: http://nginx.org/en/docs/http/ngx_http_headers_module.html 
	`,
}
