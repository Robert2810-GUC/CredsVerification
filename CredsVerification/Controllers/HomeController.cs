using HtmlAgilityPack;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Playwright;
using System.Net;
using System.Text.RegularExpressions;


namespace CredsVerification.Controllers;

[ApiController]
[Route("/")]

public class HomeController : Controller
{
    private readonly PlaywrightHolder _ph;
    public HomeController(PlaywrightHolder ph) => _ph = ph;

    public JsonResult Index()
    {
        return new JsonResult(new { success = false, message = "Login test app is currently running.." });
    }
    [HttpGet("/login")]
    public JsonResult Login()
    {
        var StateList = new List<string>
        {
        };
        return new JsonResult(new { success = false, message = "Following State's login test is supported.", states = StateList });
    }

    [HttpPost("/login")]
    public async Task<JsonResult> VerifyLogin([FromBody] LoginModel model)
    {
        try
        {
            if (string.IsNullOrEmpty(model.state))
                return new JsonResult(new { success = false, message = "State parameter is required" });

            switch (model.state.ToLower())
            {
                // Alabama
                case "al":
                    return await VerifyAlabamaLogin(model);

                // Alaska
                case "ak":
                    return await VerifyAlaskaLogin(model);

                // Arizona
                case "az":
                    //    return await VerifyArizonaLogin(model);
                    return new JsonResult(new { success = false, message = "Not opening any path for reCaptcha.Under Development...." });

                // Arkansas
                case "ar":
                    return await VerifyArkansasLogin(model);

                // California
                case "ca":
                    return await VerifyCaliforniaLogin(model);

                // Colorado
                case "co":
                    return await VerifyColoradoLoginPlaywright(model);

                // Connecticut
                case "ct":
                    return await VerifyConnecticutLogin(model);

                // Delaware
                case "de":
                    //    return await VerifyDelawareLogin(model);
                    return new JsonResult(new { success = false, message = "Under Development...." });

                // Florida
                case "fl":
                    //    return await VerifyFloridaLogin(model);
                    return new JsonResult(new { success = false, message = "Under Development...." });

                // Georgia
                case "ga":
                    return await VerifyGeorgiaLogin(model);

                // Hawaii
                case "hi":
                    return await VerifyHawaiiLogin(model);

                // Idaho
                case "id":
                    return await VerifyIdahoLogin(model);

                // Illinois
                case "il":
                    return await VerifyIllinoisLogin(model);

                // Indiana
                case "in":
                    return await VerifyIndianaLogin(model);

                // Iowa
                case "ia":
                    return await VerifyIowaLogin(model);

                // Kansas
                case "ks":
                    return await VerifyKansasLogin(model);

                // Kentucky
                case "ky":
                    return await VerifyKentuckyLogin(model);

                // Louisiana
                case "la":
                    return await VerifyLouisianaLogin(model);

                // Maine
                case "me":
                    return await VerifyMaineLogin(model);

                // Maryland
                case "md":
                    return await VerifyMarylandLogin(model);

                // Massachusetts
                case "ma":
                    return await VerifyMassachusettsLogin(model);

                // Michigan
                case "mi":
                    return await VerifyMichiganLogin(model);

                // Minnesota
                case "mn":
                    return await VerifyMinnesotaLogin(model);

                // Mississippi
                case "ms":
                    return await VerifyMississippiLogin(model);

                // Missouri
                case "mo":
                    return await VerifyMissouriLogin(model);

                // Montana
                case "mt":
                    //    return await VerifyMontanaLogin(model);
                    return new JsonResult(new { success = false, message = "Under Development...." });

                // Nebraska
                case "ne":
                    return await VerifyNebraskaLogin(model);

                // Nevada
                case "nv":
                    return await VerifyNevadaLogin(model);

                // New Hampshire
                case "nh":
                    //    return await VerifyNewHampshireLogin(model);
                    return new JsonResult(new { success = false, message = "Under Development...." });

                // New Jersey
                case "nj":
                    return await VerifyNewJerseyLogin(model);

                // New Mexico
                case "nm":
                    return await VerifyNewMexicoLogin(model);

                // New York
                case "ny":
                    return await VerifyNewYorkLogin(model);

                // North Carolina
                case "nc":
                    return await VerifyNorthCarolinaLogin(model);

                // North Dakota
                case "nd":
                    return await VerifyNorthDakotaLogin(model);

                // Ohio
                case "oh":
                    return await VerifyOhioLogin(model);

                // Oklahoma
                case "ok":
                    return await VerifyOklahomaLogin(model);

                // Oregon
                case "or":
                    //    return await VerifyOregonLogin(model);
                    return new JsonResult(new { success = false, message = "Under Development...." });

                // Pennsylvania
                case "pa":
                    return await VerifyPennsylvaniaLoginPlaywright(model);
                // Puerto Rico
                case "pr":
                    return await VerifyPuertoRicoLogin(model);

                // Rhode Island
                case "ri":
                    return await VerifyRhodeIslandLogin(model);

                // South Carolina
                case "sc":
                    return await VerifySouthCarolinaLogin(model);

                // South Dakota
                case "sd":
                    return await VerifySouthDakotaLogin(model);

                // Tennessee
                case "tn":
                    return await VerifyTennesseeLogin(model);

                // Texas
                case "tx":
                    return await VerifyTexasLogin(model);

                // Utah
                case "ut":
                    return await VerifyUtahLogin(model);

                // Vermont
                case "vt":
                    return await VerifyVermontLogin(model);

                // Virginia
                case "va":
                    return await VerifyVirginiaLogin(model);

                // Washington DC
                case "dc":
                    return await VerifyWashingtonDCLogin(model);

                // Washington 
                case "wa":
                    return await VerifyWashingtonLogin(model);

                // West Virginia
                case "wv":
                    return await VerifyWestVirginiaLogin(model);

                // Wisconsin
                case "wi":
                    return await VerifyWisconsinLogin(model);

                // Wyoming
                case "wy":
                    return await VerifyWyomingLogin(model);

                default:
                    return new JsonResult(new { success = false, message = "Unsupported state" });
            }
        }
        catch (Exception ex)
        {
            return new JsonResult(new { success = false, message = ex.Message });
        }
    }

    private static bool IsChromeError(IPage p)
    {
        var u = p.Url ?? "";
        return u.Contains("chrome-error://", StringComparison.OrdinalIgnoreCase) ||
               u.Contains("chromewebdata", StringComparison.OrdinalIgnoreCase);
    }

    [HttpGet("/Louisianalogin")]
    public async Task<JsonResult> VerifyLouisianaLogin(LoginModel model, CancellationToken ct = default)
    {
        const string LoginUrl =
        "https://remotesellersfiling.la.gov/default.aspx" +
        "?page=%2fnotice.aspx";

        // One HttpClient per app (or DI singleton) – the handler keeps cookies.
        var handler = new HttpClientHandler { CookieContainer = new CookieContainer() };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
            "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36");

        /* ------------------------------------------------------------
         * 1.  GET the login page – harvest dynamic tokens & cookies
         * ---------------------------------------------------------- */
        var html = await client.GetStringAsync(LoginUrl, ct);

        var doc = new HtmlDocument();
        doc.LoadHtml(html);

        // Helper to pull hidden‐field value by ID
        string Val(string id) => doc.GetElementbyId(id)?.Attributes["value"]?.Value ?? "";

        string viewState = Val("__VIEWSTATE");
        string viewGen = Val("__VIEWSTATEGENERATOR");
        string eventVal = Val("__EVENTVALIDATION");

        /* ------------------------------------------------------------
         * 2.  POST the filled form
         *     NB: field *names* include “ctl00$” exactly as in markup
         * ---------------------------------------------------------- */
        var form = new Dictionary<string, string>
        {
            ["__EVENTTARGET"] = "",
            ["__EVENTARGUMENT"] = "",
            ["__VIEWSTATE"] = viewState,
            ["__VIEWSTATEGENERATOR"] = viewGen,
            ["__EVENTVALIDATION"] = eventVal,
            ["UN"] = model.username,
            ["PW"] = model.password,
            ["cmdLogin2"] = "Sign In"
        };

        using var resp = await client.PostAsync(
            LoginUrl,
            new FormUrlEncodedContent(form),
            ct);

        // Follow redirect manually – faster than AutoRedirect=true when we just
        // need the target URL.  (KDOR returns 302 on success.)
        string finalUrl = resp.RequestMessage.RequestUri?.OriginalString ?? LoginUrl;

        bool success = finalUrl.Contains("remotesellersfiling.la.gov/notice.aspx",
                                         StringComparison.OrdinalIgnoreCase);

        /* ------------------------------------------------------------
         * 3.  Done – return JSON just like your original action
         * ---------------------------------------------------------- */
        return new JsonResult(new
        {
            success,
            message = success ? "Login successful." : "Invalid credentials."
        });
    }

    [HttpPost("/SouthDakotaLogin")]
    public async Task<JsonResult> VerifySouthDakotaLogin(LoginModel model)
    {
        const string LoginUrl = "https://apps.sd.gov/RV23EPath/Login.aspx";

        var browser = await _ph.GetBrowserAsync();
        var context = await browser.NewContextAsync();

        // Optional: block unnecessary resources
        await context.RouteAsync("**/*", route =>
        {
            var type = route.Request.ResourceType;
            if (type is "image" or "stylesheet" or "font")
                return route.AbortAsync();
            return route.ContinueAsync();
        });

        var page = await context.NewPageAsync();

        try
        {
            await page.GotoAsync(LoginUrl, new() { WaitUntil = WaitUntilState.NetworkIdle });

            // Fill form fields
            await page.FillAsync("input[name='ctl00$Content$txtUserName']", model.username);
            await page.FillAsync("input[name='ctl00$Content$txtPassword']", model.password);

            // Click the button
            await page.ClickAsync("input[name='ctl00$Content$btnContinue']");

            var loginResult = await Task.WhenAny(
                page.WaitForSelectorAsync("text=The username or password you have entered is incorrect", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Main Menu", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("input[id='ctl00_Content_btnExit']", new() { Timeout = 5000 })
                );

            // Now re-check the DOM safely
            if (await page.IsVisibleAsync("text=The username or password you have entered is incorrect"))
            {
                return new JsonResult(new { success = false, message = "Invalid username or password" });
            }

            if (await page.IsVisibleAsync("input[id='ctl00_Content_btnExit']") || await page.IsVisibleAsync("text=Main Menu"))
            {
                return new JsonResult(new { success = true, message = "Login successful" });
            }
            return new JsonResult(new
            {
                success = false,
                message = "Unexpected response."
            });
        }
        catch (Exception ex)
        {
            return new JsonResult(new
            {
                success = false,
                message = "Error during login: " + ex.Message
            });
        }
        finally
        {
            await context.CloseAsync();
        }
    }
    [HttpPost("/TexasLogin")]
    public async Task<JsonResult> VerifyTexasLogin(LoginModel model)
    {
        try
        {
            using (var httpClient = new HttpClient())
            {
                var jsonBody = new
                {
                    userId = model.username,
                    model.password
                };

                var jsonContent = new StringContent(System.Text.Json.JsonSerializer.Serialize(jsonBody), System.Text.Encoding.UTF8, "application/json");

                httpClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0");

                var response = await httpClient.PostAsync("https://security.app.cpa.state.tx.us/users/v2/authenticate", jsonContent);

                var responseContent = await response.Content.ReadAsStringAsync();


                if (response.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    if (responseContent.Contains("false"))
                    {
                        return new JsonResult(new { success = false, message = "Login Successful." });
                    }
                }

                if (response.StatusCode == System.Net.HttpStatusCode.UnprocessableContent)
                {
                    if (responseContent.Contains("User ID or Password is invalid"))
                    {
                        return new JsonResult(new { success = false, message = "Invalid Credentials.." });
                    }

                }
            }
            return new JsonResult(new { success = false, message = "Unexpected response from server" });

        }
        catch (Exception ex)
        {
            return new JsonResult(new
            {
                success = false,
                message = "Error during login: " + ex.Message
            });
        }
    }

    [HttpGet("/Virginialogin")]
    public async Task<JsonResult> VerifyVirginiaLogin(LoginModel model)
    {
        if (string.IsNullOrEmpty(model.accountNumber))
            return new JsonResult(new { success = false, message = "Please provide Account Number with body as key of accountNumber." });

        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false, // We want to detect the 302 redirect
            UseCookies = true,
            CookieContainer = new CookieContainer()
        };

        using var httpClient = new HttpClient(handler);
        httpClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0");

        // Step 1: GET the login page to retrieve ViewState
        var loginPageResponse = await httpClient.GetAsync("https://www.business.tax.virginia.gov/VTOL/tax/Login.xhtml");
        var loginPageHtml = await loginPageResponse.Content.ReadAsStringAsync();

        // Extract javax.faces.ViewState
        var viewStateMatch = Regex.Match(loginPageHtml, @"name=""javax\.faces\.ViewState""[^>]*value=""([^""]+)""");
        if (!viewStateMatch.Success)
            return new JsonResult(new { success = false, message = "Could not retrieve ViewState." });


        string viewState = viewStateMatch.Groups[1].Value;

        // Step 2: Submit the login form
        var formContent = new FormUrlEncodedContent(new[]
        {
        new KeyValuePair<string, string>("loginForm", "loginForm"),
        new KeyValuePair<string, string>("loginForm:customerType", "T"),
        new KeyValuePair<string, string>("loginForm:customerNumber", model.accountNumber),
        new KeyValuePair<string, string>("loginForm:userName", model.username),
        new KeyValuePair<string, string>("loginForm:password", model.password),
        new KeyValuePair<string, string>("loginForm:loginButton", "Log In"),
        new KeyValuePair<string, string>("javax.faces.ViewState", viewState),
    });

        var postResponse = await httpClient.PostAsync("https://www.business.tax.virginia.gov/VTOL/tax/Login.xhtml", formContent);
        var postContent = await postResponse.Content.ReadAsStringAsync();

        if (postResponse.StatusCode == HttpStatusCode.OK)
        {
            // Login failed, look for the error message
            if (postContent.Contains("The combination of Account Number,User ID and Password does not match our records"))
            {
                return new JsonResult(new { success = false, message = "Invalid username, password, or account number." });
            }

            return new JsonResult(new { success = false, message = "Invalid username, password, or account number." });


        }
        else if (postResponse.StatusCode == HttpStatusCode.Found)
        {
            // Login successful, follow redirect
            if (postResponse.Headers.Location != null)
            {
                var nextPageUrl = new Uri(postResponse.Headers.Location.OriginalString);
                var homePageResponse = await httpClient.GetAsync(nextPageUrl);
                var homeHtml = await homePageResponse.Content.ReadAsStringAsync();

                // Verify the customer number appears on the page
                if (homeHtml.Contains("mojarra.jsfcljs") && homeHtml.Contains("'logout':'true'"))
                {
                    return new JsonResult(new { success = true, message = "Login successful." });
                }

                return new JsonResult(new { success = true, message = "Login successful." });
            }


        }
        return new JsonResult(new { success = false, message = "Unexpected response status." });
    }
    [HttpGet("/NewYorklogin")]
    public async Task<JsonResult> VerifyNewYorkLogin(LoginModel model)
    {
        const string LoginUrl = "https://my.ny.gov/LoginV4/login.xhtml?APP=nyappdtf";

        try
        {
            // Use Firefox for stealth
            var browser = await _ph.GetBrowserAsync("firefox", false);

            var context = await browser.NewContextAsync(new BrowserNewContextOptions
            {
                ViewportSize = null,
                IgnoreHTTPSErrors = true,
                UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0"
            });

            // Hide webdriver
            var page = await context.NewPageAsync();

            await page.GotoAsync(LoginUrl, new() { Timeout = 30000 });
            await page.WaitForSelectorAsync("#loginform\\:username");

            await page.HoverAsync("#loginform\\:username");
            await page.DblClickAsync("#loginform\\:username");
            await page.Keyboard.TypeAsync(model.username, new() { Delay = 120 });

            await page.PressAsync("#loginform\\:username", "Tab");
            await page.Keyboard.TypeAsync(model.password, new() { Delay = 120 });

            // Run CAPTCHA
            await page.EvaluateAsync(@"() => {
            return new Promise((resolve, reject) => {
                grecaptcha.enterprise.ready(() => {
                    grecaptcha.enterprise.execute('6LcCiesgAAAAAPkxED9obX0-Odo6BPRIApERiXV5', {action: 'login'})
                        .then(token => {
                            document.getElementById('g-recaptcha-response').value = token;
                            resolve(true);
                        }).catch(reject);
                });
            });
        }");

            await page.WaitForTimeoutAsync(3000);

            // Confirm all fields
            await page.EvaluateAsync(@"() => {
            const altSubmit = document.querySelector('[name=""loginform: altSubmit""]');
            const formSubmit = document.querySelector('[name=""loginform_SUBMIT""]');
            if (altSubmit) altSubmit.value = '1';
            if (formSubmit) formSubmit.value = '1';
        }");

            // Optional debug log
            var token = await page.EvalOnSelectorAsync<string>("#g-recaptcha-response", "el => el.value");
            var viewState = await page.EvalOnSelectorAsync<string>("[name='javax.faces.ViewState']", "el => el.value");
            Console.WriteLine($"CAPTCHA token: {token}");
            Console.WriteLine($"ViewState: {viewState}");

            // Submit via button click
            await Task.WhenAll(
                page.ClickAsync("button[id='loginform:signinButton']"),
                page.WaitForNavigationAsync(new() { Timeout = 30000 })
            );

            var content = await page.ContentAsync();

            if (content.Contains("Invalid username") || content.Contains("incorrect password"))
                return Json(new { success = false, message = "Invalid credentials" });

            if (page.Url.Contains("dashboard") || content.Contains("Welcome") || !content.Contains("loginform"))
                return Json(new { success = true, message = "Login successful" });

            return Json(new { success = false, message = "Unknown error after login attempt" });
        }
        catch (PlaywrightException ex) when (ex.Message.Contains("ERR_CONNECTION_RESET") || ex.Message.Contains("NS_ERROR_NET_RESET"))
        {
            return Json(new { success = false, message = "Connection reset — likely blocked by server or WAF. Use proxy or stealth." });
        }
        catch (Exception ex)
        {
            return Json(new { success = false, message = $"Unhandled error: {ex.Message}" });
        }
    }
    JsonResult Json(bool ok, string msg) => new(new { success = ok, message = msg });


    [HttpGet("/Nevadalogin")]
    public async Task<JsonResult> VerifyNevadaLogin(LoginModel model)
    {
        try
        {
            using var handler = new HttpClientHandler
            {
                AllowAutoRedirect = false // so we can detect 302 manually
            };

            using var client = new HttpClient(handler);
            client.BaseAddress = new Uri("https://nevadatax.nv.gov/");
            client.DefaultRequestHeaders.Add("User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
                "(KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36");

            // 1. Load login page to get CSRF token
            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            var response = await client.SendAsync(request);

            if (response.StatusCode == HttpStatusCode.MovedPermanently || response.StatusCode == HttpStatusCode.Found)
            {
                var redirectUrl = response.Headers.Location?.ToString() ?? "unknown";
                return new JsonResult(new { success = false, message = $"Initial GET redirected to: {redirectUrl}" });
            }

            response.EnsureSuccessStatusCode();

            var loginPage = await response.Content.ReadAsStringAsync();

            // Extract CSRF token
            var token = Regex.Match(loginPage, @"name=""__RequestVerificationToken""\s+type=""hidden""\s+value=""([^""]+)""")
                             .Groups[1].Value;

            if (string.IsNullOrEmpty(token))
            {
                return new JsonResult(new { success = false, message = "CSRF token not found." });
            }

            // Step 2: Prepare login form content
            var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "__RequestVerificationToken", token },
            { "UserName", model.username },
            { "Password", model.password }
        });

            // Step 3: POST login
            var postResponse = await client.PostAsync("/", form);

            if ((int)postResponse.StatusCode == 302) // redirect after login
            {
                var location = postResponse.Headers.Location?.ToString();
                if (location != null && location.Contains("dashboard", StringComparison.OrdinalIgnoreCase))
                {
                    return new JsonResult(new { success = true, message = "Login successful." });
                }

                return new JsonResult(new
                {
                    success = true,
                    message = $"Login redirected to: {location ?? "unknown"}"
                });
            }
            else if ((int)postResponse.StatusCode == 200)
            {
                var content = await postResponse.Content.ReadAsStringAsync();
                if (content.Contains("Invalid username or password", StringComparison.OrdinalIgnoreCase))
                {
                    return new JsonResult(new { success = false, message = "Invalid username or password" });
                }

                return new JsonResult(new
                {
                    success = false,
                    message = "Login failed: Unknown error. No expected error message in content."
                });
            }

            return new JsonResult(new
            {
                success = false,
                message = $"Unexpected HTTP status from POST: {(int)postResponse.StatusCode}"
            });
        }
        catch (Exception ex)
        {
            return new JsonResult(new { success = false, message = "Error: " + ex.Message });
        }
    }
    [HttpGet("/RhodeIslandlogin")]
    public async Task<JsonResult> VerifyRhodeIslandLogin(LoginModel model)
    {
        var browser = await _ph.GetBrowserAsync();

        var context = await browser.NewContextAsync(new BrowserNewContextOptions
        {
            UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
                        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        });

        var page = await context.NewPageAsync();

        try
        {
            await page.GotoAsync("https://taxportal.ri.gov/rptp/portal/home/", new() { WaitUntil = WaitUntilState.NetworkIdle });

            // Fill form fields (all IDs/names as per original HTML)
            await page.FillAsync("input[name='userID']", model.username);
            await page.FillAsync("input[name='password']", model.password);

            await page.ClickAsync("#memberSignInButton");
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);

            var loginResult = await Task.WhenAny(
                page.WaitForSelectorAsync("text=The sign in information provided is incorrect", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Multi Factor Authentication", new() { Timeout = 5000 })
                );

            // Now re-check the DOM safely
            if (await page.IsVisibleAsync("text=The sign in information provided is incorrect"))
            {
                return new JsonResult(new { success = false, message = "Invalid username or password" });
            }
            if (await page.IsVisibleAsync("text=Multi Factor Authentication"))
            {
                return new JsonResult(new { success = true, message = "Login successful with MFA" });
            }

            // Fallback case: page did not show expected success or error indicators
            return new JsonResult(new
            {
                success = false,
                message = "Unknown login result. 'Log Out' link not found."
            });
        }
        catch (Exception ex)
        {
            return new JsonResult(new
            {
                success = false,
                message = $"Exception occurred: {ex.Message}"
            });
        }
    }

    [HttpGet("/PuertoRicoLogin")]
    public async Task<JsonResult> VerifyPuertoRicoLogin(LoginModel model)
    {
        var browser = await _ph.GetBrowserAsync();

        var context = await browser.NewContextAsync(new BrowserNewContextOptions
        {
            UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
                        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        });

        var page = await context.NewPageAsync();

        try
        {
            await page.GotoAsync("https://suri.hacienda.pr.gov/_/", new() { WaitUntil = WaitUntilState.NetworkIdle });

            // Fill form fields (all IDs/names as per original HTML)
            await page.FillAsync("input[name='Df-5']", model.username);
            await page.FillAsync("input[name='Df-6']", model.password);

            await page.ClickAsync("#Df-7");
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);

            var loginResult = await Task.WhenAny(
                page.WaitForSelectorAsync("text=Usuario y/o contraseña inválida.", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Verificar código de seguridad", new() { Timeout = 5000 })
                );

            // Now re-check the DOM safely
            if (await page.IsVisibleAsync("text=Usuario y/o contraseña inválida."))
            {
                return new JsonResult(new { success = false, message = "Invalid username or password" });
            }
            if (await page.IsVisibleAsync("text=Verificar código de seguridad"))
            {
                return new JsonResult(new { success = true, message = "Login successful with Verification Code" });
            }

            // Fallback case: page did not show expected success or error indicators
            return new JsonResult(new
            {
                success = false,
                message = "Unknown login result. 'Log Out' link not found."
            });
        }
        catch (Exception ex)
        {
            return new JsonResult(new
            {
                success = false,
                message = $"Exception occurred: {ex.Message}"
            });
        }
    }


    [HttpGet("/NewJerseylogin")]
    public async Task<JsonResult> VerifyNewJerseyLogin(LoginModel model)
    {
        var browser = await _ph.GetBrowserAsync();

        var context = await browser.NewContextAsync(new BrowserNewContextOptions
        {
            UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
                        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        });

        var page = await context.NewPageAsync();

        try
        {
            await page.GotoAsync("https://my.nj.gov/", new() { WaitUntil = WaitUntilState.NetworkIdle });

            // Fill form fields (all IDs/names as per original HTML)
            await page.FillAsync("input[name='IDToken1']", model.username);
            await page.FillAsync("input[name='IDToken2']", model.password);

            await page.ClickAsync("input[name='Login.Submit']");
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);

            var loginResult = await Task.WhenAny(
                page.WaitForSelectorAsync("text=wrong password", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=my account", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=logout", new() { Timeout = 5000 })
                );

            // Now re-check the DOM safely
            if (await page.IsVisibleAsync("text=wrong password"))
            {
                return new JsonResult(new { success = false, message = "Invalid username or password" });
            }
            if (await page.IsVisibleAsync("text=logout") || await page.IsVisibleAsync("text=my account"))
            {
                return new JsonResult(new { success = true, message = "Login successful" });
            }

            // Fallback case: page did not show expected success or error indicators
            return new JsonResult(new
            {
                success = false,
                message = "Unknown login result. 'Log Out' link not found."
            });
        }
        catch (Exception ex)
        {
            return new JsonResult(new
            {
                success = false,
                message = $"Exception occurred: {ex.Message}"
            });
        }
    }

    [HttpGet("/NorthCarolinaLogin")]

    public async Task<JsonResult> VerifyNorthCarolinaLogin(LoginModel model)
    {
        if (string.IsNullOrEmpty(model.accountNumber))
            return new JsonResult(new { success = false, message = "Please provide Account Number with body as key of accountNumber." });

        var browser = await _ph.GetBrowserAsync();

        var context = await browser.NewContextAsync(new BrowserNewContextOptions
        {
            UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
                        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        });

        var page = await context.NewPageAsync();

        try
        {
            // Step 1: Open NC eServices contact page
            await page.GotoAsync("https://eservices.dor.nc.gov/sau/contact.jsp", new() { WaitUntil = WaitUntilState.NetworkIdle });

            // Fill test contact info
            await page.FillAsync("input[name='name']", "Test User");
            await page.FillAsync("input[name='email']", "test@example.com");
            await page.FillAsync("input[name='phone']", "9999999999");

            // Click "Next"
            await page.ClickAsync("a[href*=\"GenSalesAcctServlet\"] img[alt='next']");

            // Wait for account input page
            await page.WaitForSelectorAsync("input[name='salesacctnumber']", new() { Timeout = 10000 });

            // Step 2: Fill account number
            await page.FillAsync("input[name='salesacctnumber']", model.accountNumber); // using username as Account ID
            await page.ClickAsync("a[href*='checkSalesAccountNumber'] img[alt='submit']");

            // Handle possible JavaScript alert (invalid ID)
            page.Dialog += async (_, dialog) =>
            {
                if (dialog.Message.Contains("You have not entered a valid Account ID"))
                    await dialog.AcceptAsync();
            };

            await page.WaitForTimeoutAsync(3000);

            // Step 3: Check for valid account verification info
            bool hasAccountTable = await page.IsVisibleAsync("text=Verify the following information");
            if (hasAccountTable)
            {
                // Extract info
                string accountId = await page.TextContentAsync("xpath=(//b[contains(text(),'Account ID')]/following::font)[1]");
                string businessName = await page.TextContentAsync("xpath=(//b[contains(text(),'Legal/Business Name')]/following::font)[1]");

                return new JsonResult(new
                {
                    success = true,
                    accountId = accountId?.Trim(),
                    businessName = businessName?.Trim(),
                    message = "Account verified successfully."
                });
            }

            // If we reach here, assume invalid
            return new JsonResult(new
            {
                success = false,
                message = "Invalid or unknown account ID"
            });
        }
        catch (Exception ex)
        {
            return new JsonResult(new
            {
                success = false,
                message = $"Exception occurred: {ex.Message}"
            });
        }
        finally
        {
            await context.CloseAsync();
        }
    }




    [HttpGet("/Kansaslogin")]
    public async Task<JsonResult> VerifyKansasLogin(LoginModel model, CancellationToken ct = default)
    {
        const string LoginUrl =
        "https://www.kdor.ks.gov/Apps/kcsc/login.aspx" +
        "?ReturnUrl=%2fapps%2fkcsc%2fsecure%2fdefault.aspx";

        // One HttpClient per app (or DI singleton) – the handler keeps cookies.
        var handler = new HttpClientHandler { CookieContainer = new CookieContainer() };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
            "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36");

        /* ------------------------------------------------------------
         * 1.  GET the login page – harvest dynamic tokens & cookies
         * ---------------------------------------------------------- */
        var html = await client.GetStringAsync(LoginUrl, ct);

        var doc = new HtmlDocument();
        doc.LoadHtml(html);

        // Helper to pull hidden‐field value by ID
        string Val(string id) => doc.GetElementbyId(id)?.Attributes["value"]?.Value ?? "";

        string viewState = Val("__VIEWSTATE");
        string viewGen = Val("__VIEWSTATEGENERATOR");
        string eventVal = Val("__EVENTVALIDATION");

        /* ------------------------------------------------------------
         * 2.  POST the filled form
         *     NB: field *names* include “ctl00$” exactly as in markup
         * ---------------------------------------------------------- */
        var form = new Dictionary<string, string>
        {
            ["__EVENTTARGET"] = "",
            ["__EVENTARGUMENT"] = "",
            ["__VIEWSTATE"] = viewState,
            ["__VIEWSTATEGENERATOR"] = viewGen,
            ["__EVENTVALIDATION"] = eventVal,
            ["ctl00$cphBody$txtUserName"] = model.username,
            ["ctl00$cphBody$txtPassword"] = model.password,
            ["ctl00$cphBody$cmdSignIn"] = "Sign In"
        };

        using var resp = await client.PostAsync(
            LoginUrl,
            new FormUrlEncodedContent(form),
            ct);

        // Follow redirect manually – faster than AutoRedirect=true when we just
        // need the target URL.  (KDOR returns 302 on success.)
        string finalUrl = resp.RequestMessage.RequestUri?.OriginalString ?? LoginUrl;

        bool success = finalUrl.Contains("/kcsc/secure/default.aspx",
                                         StringComparison.OrdinalIgnoreCase);

        /* ------------------------------------------------------------
         * 3.  Done – return JSON just like your original action
         * ---------------------------------------------------------- */
        return new JsonResult(new
        {
            success,
            message = success ? "Login successful." : "Invalid credentials."
        });
    }

    [HttpGet("/Wyominglogin")]
    public async Task<JsonResult> VerifyWyomingLogin(LoginModel model)
    {
        var browser = await _ph.GetBrowserAsync();

        var context = await browser.NewContextAsync(new BrowserNewContextOptions
        {
            UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
                        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        });

        var page = await context.NewPageAsync();

        try
        {
            await page.GotoAsync("https://excise-wyifs.wy.gov/default.aspx?ReturnUrl=%2fSalesUse%2fMain.aspx", new() { WaitUntil = WaitUntilState.NetworkIdle });

            await page.ClickAsync("span[class='close']");
            // Fill form fields (all IDs/names as per original HTML)
            await page.FillAsync("input[name='ctl00$CenterContent$txtUserName']", model.username);
            await page.FillAsync("input[name='ctl00$CenterContent$txtPassword']", model.password);
            await page.FillAsync("input[name='ctl00$CenterContent$txtPin']", model.pin);

            await page.ClickAsync("input[name='ctl00$CenterContent$btnSignIn']");
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);

            // Check for login failure message span
            var errorVisible = await page.Locator("#ctl00_CenterContent_lblErrorMessage").IsVisibleAsync();

            if (errorVisible)
            {
                return new JsonResult(new
                {
                    success = false,
                    message = "Invalid credentials. Login failed."
                });
            }

            // Look for the 'Log Out' anchor with class 'biggertext'
            var logoutVisible = await page.Locator("a.biggertext", new() { HasTextString = "Log Out" }).IsVisibleAsync();

            if (logoutVisible)
            {
                return new JsonResult(new
                {
                    success = true,
                    message = "Login successful."
                });
            }

            // Fallback case: page did not show expected success or error indicators
            return new JsonResult(new
            {
                success = false,
                message = "Unknown login result. 'Log Out' link not found."
            });
        }
        catch (Exception ex)
        {
            return new JsonResult(new
            {
                success = false,
                message = $"Exception occurred: {ex.Message}"
            });
        }
    }



    [HttpGet("/Washingtonlogin")]
    public async Task<JsonResult> VerifyWashingtonLogin(LoginModel model)
    {
        var browser = await _ph.GetBrowserAsync();

        var context = await browser.NewContextAsync(new()
        {
            UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
                        "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        });

        var page = await context.NewPageAsync();

        try
        {
            await page.GotoAsync("https://secure.dor.wa.gov/home/Login", new() { WaitUntil = WaitUntilState.NetworkIdle });

            await page.FillAsync("#username", model.username);
            await page.FillAsync("#password", model.password);

            await page.ClickAsync("#signin");

            // Wait for navigation after clicking sign in
            await page.WaitForLoadStateAsync(LoadState.NetworkIdle);

            // Capture final URL after login attempt
            var finalUrl = page.Url;

            if (finalUrl.Contains("rfs=BadLogin", StringComparison.OrdinalIgnoreCase))
            {
                return new JsonResult(new
                {
                    success = false,
                    message = "Invalid credentials. Login failed."
                });
            }

            if (finalUrl.Contains("rfs=ActiveSession", StringComparison.OrdinalIgnoreCase) ||
                finalUrl.Contains("mga/sps/authsvc?TransactionId=", StringComparison.OrdinalIgnoreCase) ||
                finalUrl.Contains("/home/mydor", StringComparison.OrdinalIgnoreCase))
            {
                return new JsonResult(new
                {
                    success = true,
                    message = "Login successful."
                });
            }

            // Catch unknown flow
            return new JsonResult(new
            {
                success = false,
                message = $"Unexpected response. URL: {finalUrl}"
            });
        }
        catch (Exception ex)
        {
            return new JsonResult(new
            {
                success = false,
                message = $"Exception occurred: {ex.Message}"
            });
        }
    }


    [HttpGet("/Pennsylvanialogin")]
    public async Task<JsonResult> VerifyPennsylvaniaLoginPlaywright(LoginModel model)
    {
        return await LoginByBrowserAutomate(model, "https://mypath.pa.gov/_/");
    }

    [HttpGet("/Coloradologin")]
    public async Task<JsonResult> VerifyColoradoLoginPlaywright(LoginModel model)
    {
        return await LoginByBrowserAutomate(model, "https://www.colorado.gov/revenueonline/_/");
    }
    [HttpGet("/Californialogin")]
    public async Task<JsonResult> VerifyCaliforniaLogin(LoginModel model)
    {
        var browser = await _ph.GetBrowserAsync();

        var context = await browser.NewContextAsync();

        await context.RouteAsync("**/*", route =>
        {
            var t = route.Request.ResourceType;
            if (t is "image" or "stylesheet" or "font")
                return route.AbortAsync();
            return route.ContinueAsync();
        });


        var page = await context.NewPageAsync();

        try
        {
            await page.GotoAsync("https://onlineservices.cdtfa.ca.gov/_/");

            await page.FillAsync("input[name='f-6']", model.username);
            await page.FillAsync("input[name='f-7']", model.password);

            // simulate clicking or triggering the submit
            await page.ClickAsync("#f-8");



            // Wait for the next response or check some indicator
            // Wait for either success or error indicator
            var loginResult = await Task.WhenAny(
                page.WaitForSelectorAsync("text=Invalid username", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Confirm Identification", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Logout", new() { Timeout = 5000 }) // or any valid post-login text
            );

            // Now re-check the DOM safely
            if (await page.IsVisibleAsync("text=Invalid user name") || await page.IsVisibleAsync("text=Invalid username"))
            {
                return new JsonResult(new { success = false, message = "Invalid username or password" });
            }

            if (await page.IsVisibleAsync("text=Confirm Identification"))
            {
                return new JsonResult(new
                {
                    success = true,
                    message = "Login successful but requires security code verification"
                });
            }
            if (await page.IsVisibleAsync("text=Logout"))
            {
                return new JsonResult(new { success = true, message = "Login successful" });
            }


            return new JsonResult(new { success = false, message = "There is an issue." });

        }
        catch (Exception ex)
        {
            return new JsonResult(new { success = false, message = ex.Message });
        }
    }
    [HttpGet("/ohiologin")]
    public async Task<JsonResult> VerifyOhioLogin(LoginModel model)
    {
        var browser = await _ph.GetBrowserAsync();
        var context = await browser.NewContextAsync();

        // Optional: block heavy resources
        await context.RouteAsync("**/*", route =>
        {
            var t = route.Request.ResourceType;
            if (t is "image" or "stylesheet" or "font")
                return route.AbortAsync();

            return route.ContinueAsync();
        });

        var page = await context.NewPageAsync();

        try
        {
            // 1. Go to Ohio portal
            await page.GotoAsync("https://myportal.tax.ohio.gov/tap/_/");

            // 2. Click "Log in or Create an OHID Account" button
            //    (id + visible text, in case the id changes in future)
            await page.ClickAsync("button#Dd-g-1:has-text('Log in or Create an OHID Account')");

            // 3. Wait for OHID login page / form
            await page.WaitForSelectorAsync("form.ohid-login__form input#login-username", new() { Timeout = 15000 });

            // 4. Fill credentials
            await page.FillAsync("#login-username", model.username);
            await page.FillAsync("#login-password", model.password);

            // 5. Submit
            await page.ClickAsync("#login-submit");

            // 6. Wait for either:
            //    - invalid credentials alert
            //    - two-step verification modal
            var firstResult = await Task.WhenAny(
                page.WaitForSelectorAsync("text=We didn't recognize the username or password you entered", new() { Timeout = 15000 }),
                page.WaitForSelectorAsync("text=Two-step verification", new() { Timeout = 15000 })
            );

            // 7. Now inspect what is actually visible

            // Invalid username/password alert
            if (await page.IsVisibleAsync("text=We didn't recognize the username or password you entered"))
            {
                return new JsonResult(new
                {
                    success = false,
                    message = "Invalid username or password"
                });
            }

            // Valid credentials -> two-step verification
            if (await page.IsVisibleAsync("text=Two-step verification"))
            {
                return new JsonResult(new
                {
                    success = true,
                    message = "Login successful but requires two-step verification"
                });
            }

            // Fallback: neither invalid message nor 2FA text was found
            return new JsonResult(new
            {
                success = false,
                message = "Unable to determine login status. The page layout may have changed."
            });
        }
        catch (Exception ex)
        {
            return new JsonResult(new
            {
                success = false,
                message = ex.Message
            });
        }
        finally
        {
            await context.CloseAsync();
        }
    }

    [HttpGet("/newmexicologin")]
    public async Task<JsonResult> VerifyNewMexicoLogin(LoginModel model)
    {
        var browser = await _ph.GetBrowserAsync();
        var context = await browser.NewContextAsync();

        // Optional: block unnecessary resources
        await context.RouteAsync("**/*", route =>
        {
            var t = route.Request.ResourceType;
            if (t is "image" or "stylesheet" or "font")
                return route.AbortAsync();

            return route.ContinueAsync();
        });

        var page = await context.NewPageAsync();

        try
        {
            // 1. Go to New Mexico TAP portal
            await page.GotoAsync("https://tap.state.nm.us/Tap/_/");

            // 2. Wait for username (Logon) field & Login button
            await page.WaitForSelectorAsync("#Dd-9", new() { Timeout = 15000 });
            await page.WaitForSelectorAsync("#Dd-b", new() { Timeout = 15000 });

            // 3. Fill username (Logon)
            await page.FillAsync("#Dd-9", model.username);

            // 4. Click "Log in"
            await page.ClickAsync("#Dd-b");

            // 5. Wait for either:
            //    - username doesn't exist message
            //    - password screen (input #Dc-i)
            var firstResult = await Task.WhenAny(
                page.WaitForSelectorAsync(
                    "text=An account with this username doesn't exist",
                    new() { Timeout = 15000 }),
                page.WaitForSelectorAsync("#Dc-i", new() { Timeout = 15000 })
            );

            // 6. Check if username is invalid
            if (await page.IsVisibleAsync(
                    "text=An account with this username doesn't exist"))
            {
                return new JsonResult(new
                {
                    success = false,
                    stage = "username",
                    message = "An account with this username doesn't exist."
                });
            }

            // 7. If we don't see the password field, we can't continue reliably
            if (!await page.IsVisibleAsync("#Dc-i"))
            {
                return new JsonResult(new
                {
                    success = false,
                    stage = "username",
                    message = "Unable to reach password page. The site layout may have changed."
                });
            }

            // 8. We are on the password page now
            await page.FillAsync("#Dc-i", model.password);

            // Optional: you could check/uncheck "Trust this device" here (#Dc-k) if you want

            // 9. Click second "Log In" button
            await page.ClickAsync("#Dc-l");

            // 10. Wait for either:
            //     - Invalid username/password
            //     - Two-Step Verification
            var secondResult = await Task.WhenAny(
                page.WaitForSelectorAsync(
                    "text=Invalid username",
                    new() { Timeout = 15000 }),
                page.WaitForSelectorAsync(
                    "text=Two-Step Verification",
                    new() { Timeout = 15000 })
            );

            // Invalid password
            if (await page.IsVisibleAsync(
                    "text=Invalid username"))
            {
                return new JsonResult(new
                {
                    success = false,
                    stage = "password",
                    message = "Invalid username and/or password."
                });
            }

            // Valid credentials -> goes to Two-Step Verification
            if (await page.IsVisibleAsync(
                    "text=Two-Step Verification"))
            {
                return new JsonResult(new
                {
                    success = true,
                    stage = "two_step",
                    message = "Login successful but requires two-step verification."
                });
            }

            // Fallback
            return new JsonResult(new
            {
                success = false,
                message = "Unable to determine login status. The page layout may have changed."
            });
        }
        catch (Exception ex)
        {
            return new JsonResult(new
            {
                success = false,
                message = ex.Message
            });
        }
        finally
        {
            await context.CloseAsync();
        }
    }

    [HttpGet("/Georgialogin")]
    public async Task<JsonResult> VerifyGeorgiaLogin(LoginModel model)
    {
        return await LoginByBrowserAutomate(model, "https://gtc.dor.ga.gov/_/");
    }
    [HttpGet("/Mainelogin")]
    public async Task<JsonResult> VerifyMaineLogin(LoginModel model)
    {
        return await LoginByBrowserAutomate(model, "https://revenue.maine.gov/_/");
    }
    [HttpGet("/Alabamalogin")]
    public async Task<JsonResult> VerifyAlabamaLogin(LoginModel model)
    {
        return await LoginByBrowserAutomate(model, "https://myalabamataxes.alabama.gov/tap/_/", "Protect your My Alabama Taxes profile with two-step verification");
    }
    [HttpGet("/Arkansaslogin")]
    public async Task<JsonResult> VerifyArkansasLogin(LoginModel model)
    {
        return await LoginByBrowserAutomate(model, "https://atap.arkansas.gov/_/", "Welcome");
    }
    [HttpGet("/Illinoislogin")]
    public async Task<JsonResult> VerifyIllinoisLogin(LoginModel model)
    {
        var browser = await _ph.GetBrowserAsync();

        var context = await browser.NewContextAsync();

        await context.RouteAsync("**/*", route =>
        {
            var t = route.Request.ResourceType;
            if (t is "image" or "stylesheet" or "font")
                return route.AbortAsync();
            return route.ContinueAsync();
        });


        var page = await context.NewPageAsync();

        try
        {
            await page.GotoAsync("https://mytax.illinois.gov/_/");

            await page.FillAsync("input[name='Df-5']", model.username);
            await page.FillAsync("input[name='Df-6']", model.password);

            // simulate clicking or triggering the submit
            await page.ClickAsync("#Df-7");



            // Wait for the next response or check some indicator
            // Wait for either success or error indicator
            var loginResult = await Task.WhenAny(
                page.WaitForSelectorAsync("text=Invalid user name", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Invalid username", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Login and password combination is invalid", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Verify Security Code", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Protect your MyTax profile with two-step verification", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Logout", new() { Timeout = 5000 })
            );

            // Now re-check the DOM safely
            if (await page.IsVisibleAsync("text=Invalid user name") || await page.IsVisibleAsync("text=Invalid username") || await page.IsVisibleAsync("text=Login and password combination is invalid") || await page.IsVisibleAsync("text=Invalid Login ID"))
            {
                return new JsonResult(new { success = false, message = "Invalid username or password" });
            }

            if (await page.IsVisibleAsync("text=Verify Security Code") || await page.IsVisibleAsync("text=Protect your MyTax profile with two-step verification"))
            {
                return new JsonResult(new
                {
                    success = true,
                    message = "Login successful but requires security code verification"
                });
            }
            if (await page.IsVisibleAsync("text=Logout"))
            {
                return new JsonResult(new { success = true, message = "Login successful" });
            }


            return new JsonResult(new { success = false, message = "There is an issue." });

        }
        catch (Exception ex)
        {
            return new JsonResult(new { success = false, message = ex.Message });
        }
    }
    [HttpGet("/Connecticutlogin")]
    public async Task<JsonResult> VerifyConnecticutLogin(LoginModel model)
    {
        return await LoginByBrowserAutomateByIdsDd8andDd9(model, "https://drs.ct.gov/eservices/_/", verifyPoint: "Protect your myconneCT profile with two-step verification");
    }
    [HttpGet("/Hawaiilogin")]
    public async Task<JsonResult> VerifyHawaiiLogin(LoginModel model)
    {
        return await LoginByBrowserAutomateByIdsDd8andDd9(model, "https://hitax.hawaii.gov/_/", verifyPoint: "Protect your Hawaii Tax Online profile with two-step verification");
    }
    [HttpGet("/Indianalogin")]
    public async Task<JsonResult> VerifyIndianaLogin(LoginModel model)
    {
        return await LoginByBrowserAutomateByIdsDd8andDd9(model, "https://intime.dor.in.gov/eServices/_/", verifyPoint: "Protect your Indiana Tax Online profile with two-step verification");
    }
    [HttpGet("/Iowalogin")]
    public async Task<JsonResult> VerifyIowaLogin(LoginModel model)
    {
        return await LoginByBrowserAutomateByIdsDd8andDd9(model, "https://govconnect.iowa.gov/tap/_/", verifyPoint: "Protect your GovConnectIowa profile with two-step verification");
    }

    private async Task<JsonResult> VerifyAlaskaLogin(LoginModel model)
    {
        using (var httpClient = new HttpClient())
        {
            // Prepare the form data
            var formContent = new FormUrlEncodedContent(new[]
            {
            new KeyValuePair<string, string>("login_username", model.username),
            new KeyValuePair<string, string>("login_password", model.password),
            new KeyValuePair<string, string>("login_return_to", ""),
            new KeyValuePair<string, string>("submitbutton", "Log In")
        });

            // Disable automatic redirect following so we can check the status code
            httpClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0");
            var response = await httpClient.PostAsync("https://arsstc.munirevs.com/log-in/", formContent);

            // If status is 302, login was successful
            if (response.StatusCode == System.Net.HttpStatusCode.Found)
            {
                return new JsonResult(new { success = true });
            }

            // If status is 200, check for error message in response
            if (response.StatusCode == System.Net.HttpStatusCode.OK)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                if (responseContent.Contains("Invalid Credentials.."))
                {
                    return new JsonResult(new { success = false, message = "Invalid Credentials.." });
                }
                else
                {
                    if (responseContent.Contains("Log Out"))
                    {
                        return new JsonResult(new { success = true, message = "Yes, It's Alaska's valid credentials" });
                    }
                }
            }

            return new JsonResult(new { success = false, message = "Unexpected response from server" });
        }
    }



    private async Task<JsonResult> LoginByBrowserAutomateByIdsDd8andDd9(LoginModel model, string LoginUrl, string successPoint = "Log Out", string verifyPoint = "Verify Security Code")
    {
        var browser = await _ph.GetBrowserAsync();

        var context = await browser.NewContextAsync();

        await context.RouteAsync("**/*", route =>
        {
            var t = route.Request.ResourceType;
            if (t is "image" or "stylesheet" or "font")
                return route.AbortAsync();
            return route.ContinueAsync();
        });


        var page = await context.NewPageAsync();

        try
        {
            await page.GotoAsync(LoginUrl);

            await page.FillAsync("input[name='Dd-8']", model.username);
            await page.FillAsync("input[name='Dd-9']", model.password);

            // simulate clicking or triggering the submit
            await page.ClickAsync("#Dd-a");



            // Wait for the next response or check some indicator
            // Wait for either success or error indicator
            var loginResult = await Task.WhenAny(
                page.WaitForSelectorAsync("text=Invalid user name", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Invalid username", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Invalid Username", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Verify Security Code", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync($"text={successPoint}", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync($"text={verifyPoint}", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Logout", new() { Timeout = 5000 })
            );

            // Now re-check the DOM safely
            if (await page.IsVisibleAsync("text=Invalid user name") || await page.IsVisibleAsync("text=Invalid username") || await page.IsVisibleAsync("text=Invalid Username") || await page.IsVisibleAsync("text=Invalid Login ID"))
            {
                return new JsonResult(new { success = false, message = "Invalid username or password" });
            }

            if (await page.IsVisibleAsync("text=Verify Security Code") || await page.IsVisibleAsync($"text={verifyPoint}"))
            {
                return new JsonResult(new
                {
                    success = true,
                    message = "Login successful but requires security code verification"
                });
            }
            if (await page.IsVisibleAsync("text=Logout") || await page.IsVisibleAsync($"text={successPoint}"))
            {
                return new JsonResult(new { success = true, message = "Login successful" });
            }


            return new JsonResult(new { success = false, message = "There is an issue." });

        }
        catch (Exception ex)
        {
            return new JsonResult(new { success = false, message = ex.Message });
        }
    }
    private async Task<JsonResult> LoginByBrowserAutomate(LoginModel model, string LoginUrl, string successPoint = "Log Out")
    {
        var browser = await _ph.GetBrowserAsync();

        var context = await browser.NewContextAsync();

        await context.RouteAsync("**/*", route =>
        {
            var t = route.Request.ResourceType;
            if (t is "image" or "stylesheet" or "font")
                return route.AbortAsync();
            return route.ContinueAsync();
        });


        var page = await context.NewPageAsync();

        try
        {
            await page.GotoAsync(LoginUrl);

            await page.FillAsync("input[name='Dd-5']", model.username);
            await page.FillAsync("input[name='Dd-6']", model.password);

            // simulate clicking or triggering the submit
            await page.ClickAsync("#Dd-7");



            // Wait for the next response or check some indicator
            // Wait for either success or error indicator
            var loginResult = await Task.WhenAny(
                page.WaitForSelectorAsync("text=Invalid user name", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Invalid Username", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Your login details are incorrect", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Username and Password Combination Invalid", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Username and password combination is invalid", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Invalid Login ID", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Verify Security Code", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync($"text={successPoint}", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Logout", new() { Timeout = 5000 }) // or any valid post-login text
            );

            // Now re-check the DOM safely
            if (await page.IsVisibleAsync("text=Invalid user name") ||
                await page.IsVisibleAsync("text=Invalid Username") ||
                await page.IsVisibleAsync("text=Your login details are incorrect") ||
                await page.IsVisibleAsync("text=Username and Password Combination Invalid") ||
                await page.IsVisibleAsync("text=Username and password combination is invalid") ||
                await page.IsVisibleAsync("text=Invalid Login ID"))
            {
                return new JsonResult(new { success = false, message = "Invalid username or password" });
            }

            if (await page.IsVisibleAsync("text=Verify Security Code"))
            {
                return new JsonResult(new
                {
                    success = true,
                    message = "Login successful but requires security code verification"
                });
            }
            if (await page.IsVisibleAsync("text=Logout") || await page.IsVisibleAsync($"text={successPoint}"))
            {
                return new JsonResult(new { success = true, message = "Login successful" });
            }


            return new JsonResult(new { success = false, message = "There is an issue." });

        }
        catch (Exception ex)
        {
            return new JsonResult(new { success = false, message = ex.Message });
        }
    }
    private async Task<JsonResult> VerifyIdahoLogin(LoginModel model)
    {
        return await LoginByBrowserAutomate(model, "https://idahotap.gentax.com/TAP/_/", "Two-Step Verification Setup");
    }

    private async Task<JsonResult> VerifyUtahLogin(LoginModel model)
    {
        return await LoginByBrowserAutomate(model, "https://tap.tax.utah.gov/TAXExpress/_/", "Two-Step Verification Setup");
    }
    private async Task<JsonResult> VerifyMassachusettsLogin(LoginModel model)
    {
        return await LoginByBrowserAutomate(model, "https://mtc.dor.state.ma.us/mtc/_/", "Two-Step Verification Setup");
    }
    private async Task<JsonResult> VerifyMinnesotaLogin(LoginModel model)
    {
        return await LoginByBrowserAutomate(model, "https://www.mndor.state.mn.us/tp/eservices/_/", "Two-Step Verification Setup");
    }

    private async Task<JsonResult> VerifyNorthDakotaLogin(LoginModel model)
    {
        return await LoginByBrowserAutomate(model, "https://apps.nd.gov/tax/tap/_/", "Two-Step Verification Setup");
    }
    private async Task<JsonResult> VerifyOklahomaLogin(LoginModel model)
    {
        return await LoginByBrowserAutomate(model, "https://oktap.tax.ok.gov/OkTAP/Web/_/", "Verify Security Code");
    }
    private async Task<JsonResult> VerifyTennesseeLogin(LoginModel model)
    {
        return await LoginByBrowserAutomate(model, "https://tntap.tn.gov/eservices/_/", "two-step verification");
    }
    private async Task<JsonResult> VerifyVermontLogin(LoginModel model)
    {
        return await LoginByBrowserAutomate(model, "https://www.myvtax.vermont.gov/_/", "Verify Security Code");
    }
    private async Task<JsonResult> VerifyWestVirginiaLogin(LoginModel model)
    {
        return await LoginByBrowserAutomate(model, "https://mytaxes.wvtax.gov/_/", "Verify Security Code");
    }
    private async Task<JsonResult> VerifyWisconsinLogin(LoginModel model)
    {
        return await LoginByBrowserAutomate(model, "https://tap.revenue.wi.gov/mta/_/", "Verify Security Code");
    }

    private async Task<JsonResult> VerifyMississippiLogin(LoginModel model)
    {
        return await LoginByBrowserAutomateByIdsDd8andDd9(model, "https://tap.dor.ms.gov/_/", "Verify Security Code");
    }
    private async Task<JsonResult> VerifySouthCarolinaLogin(LoginModel model)
    {
        var browser = await _ph.GetBrowserAsync();

        var context = await browser.NewContextAsync();

        await context.RouteAsync("**/*", route =>
        {
            var t = route.Request.ResourceType;
            if (t is "image" or "stylesheet" or "font")
                return route.AbortAsync();
            return route.ContinueAsync();
        });


        var page = await context.NewPageAsync();

        try
        {
            await page.GotoAsync("https://mydorway.dor.sc.gov/_/");

            await page.FillAsync("input[name='Df-9']", model.username);
            await page.FillAsync("input[name='Df-a']", model.password);

            // simulate clicking or triggering the submit
            await page.ClickAsync("#Df-b");



            // Wait for the next response or check some indicator
            // Wait for either success or error indicator
            var loginResult = await Task.WhenAny(
                page.WaitForSelectorAsync("text=Invalid user name", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Invalid username", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Invalid Username", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Invalid username and/or password.", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Verify Security Code", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Logout", new() { Timeout = 5000 })
            );

            // Now re-check the DOM safely
            if (await page.IsVisibleAsync("text=Invalid user name") ||
                await page.IsVisibleAsync("text=Invalid username") ||
                await page.IsVisibleAsync("text=Invalid Username") ||
                await page.IsVisibleAsync("text=Invalid username and/or password.") ||
                await page.IsVisibleAsync("text=Invalid Login ID"))
            {
                return new JsonResult(new { success = false, message = "Invalid username or password" });
            }

            if (await page.IsVisibleAsync("text=Verify Security Code"))
            {
                return new JsonResult(new
                {
                    success = true,
                    message = "Login successful but requires security code verification"
                });
            }
            if (await page.IsVisibleAsync("text=Logout"))
            {
                return new JsonResult(new { success = true, message = "Login successful" });
            }


            return new JsonResult(new { success = false, message = "There is an issue." });

        }
        catch (Exception ex)
        {
            return new JsonResult(new { success = false, message = ex.Message });
        }
    }

    private async Task<JsonResult> VerifyMissouriLogin(LoginModel model)
    {
        var browser = await _ph.GetBrowserAsync();

        var context = await browser.NewContextAsync();

        await context.RouteAsync("**/*", route =>
        {
            var t = route.Request.ResourceType;
            if (t is "image" or "stylesheet" or "font")
                return route.AbortAsync();
            return route.ContinueAsync();
        });


        var page = await context.NewPageAsync();

        try
        {
            await page.GotoAsync("https://mytax.mo.gov/rptp/portal/home/");

            await page.FillAsync("input[name='userID']", model.username);
            await page.FillAsync("input[name='password']", model.password);

            // simulate clicking or triggering the submit
            await page.ClickAsync("#memberSignInButton");



            // Wait for the next response or check some indicator
            // Wait for either success or error indicator
            var loginResult = await Task.WhenAny(
                page.WaitForSelectorAsync("text=Invalid user name", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Invalid Username", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Your login details are incorrect", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=The sign in information provided is incorrect.", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Invalid Login ID", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Verify Security Code", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Two-Step Verification", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Incorrect login info", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Log Out", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Welcome", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Logout", new() { Timeout = 5000 }) // or any valid post-login text
            );

            // Now re-check the DOM safely
            if (await page.IsVisibleAsync("text=Invalid user name") ||
                await page.IsVisibleAsync("text=Invalid Username") ||
                await page.IsVisibleAsync("text=Your login details are incorrect") ||
                await page.IsVisibleAsync("text=The sign in information provided is incorrect.") ||
                await page.IsVisibleAsync("text=Invalid Login ID"))
            {
                return new JsonResult(new { success = false, message = "Invalid username or password" });
            }

            if (await page.IsVisibleAsync("text=Verify Security Code") || await page.IsVisibleAsync("text=Two-Step Verification"))
            {
                return new JsonResult(new
                {
                    success = true,
                    message = "Login successful but requires security code verification"
                });
            }
            if (await page.IsVisibleAsync("text=Logout") || await page.IsVisibleAsync("text=Log Out") || await page.IsVisibleAsync("text=Welcome"))
            {
                return new JsonResult(new { success = true, message = "Login successful" });
            }


            return new JsonResult(new { success = false, message = "There is an issue." });

        }
        catch (Exception ex)
        {
            return new JsonResult(new { success = false, message = ex.Message });
        }
    }


    private async Task<JsonResult> VerifyNebraskaLogin(LoginModel model)
    {
        if (string.IsNullOrEmpty(model.accountNumber))
            return new JsonResult(new { success = false, message = "Please provide Nebraska ID with body as key of accountNumber." });

        if (string.IsNullOrEmpty(model.pin))
            return new JsonResult(new { success = false, message = "Please provide Pin with body as key of pin." });
        var browser = await _ph.GetBrowserAsync(headless: false);

        var context = await browser.NewContextAsync();

        await context.RouteAsync("**/*", route =>
        {
            var t = route.Request.ResourceType;
            if (t is "image" or "stylesheet" or "font")
                return route.AbortAsync();
            return route.ContinueAsync();
        });


        var page = await context.NewPageAsync();

        try
        {
            await page.GotoAsync("https://ndr-efs.ne.gov/revefs/allPages/login.faces");

            await page.FillAsync("input[name='j_id32:stateId']", model.accountNumber);
            await page.FillAsync("input[name='j_id32:j_id65']", model.pin);

            // simulate clicking or triggering the submit
            await page.ClickAsync("#j_id32\\:j_id70");



            // Wait for the next response or check some indicator
            // Wait for either success or error indicator
            var loginResult = await Task.WhenAny(
                page.WaitForSelectorAsync("text=Verify Security Code", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Two-Step Verification", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Incorrect login info", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Log Out", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Welcome", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Logout", new() { Timeout = 5000 })
            );

            // Now re-check the DOM safely
            if (await page.IsVisibleAsync("text=Incorrect login info"))
            {
                return new JsonResult(new { success = false, message = "Invalid login info" });
            }

            if (await page.IsVisibleAsync("text=Verify Security Code") || await page.IsVisibleAsync("text=Two-Step Verification"))
            {
                return new JsonResult(new
                {
                    success = true,
                    message = "Login successful but requires security code verification"
                });
            }
            if (await page.IsVisibleAsync("text=Logout") || await page.IsVisibleAsync("text=Log Out") || await page.IsVisibleAsync("text=Welcome"))
            {
                return new JsonResult(new { success = true, message = "Login successful" });
            }


            return new JsonResult(new { success = false, message = "There is an issue." });

        }
        catch (Exception ex)
        {
            return new JsonResult(new { success = false, message = ex.Message });
        }
    }



    private async Task<JsonResult> VerifyWashingtonDCLogin(LoginModel model)
    {
        var browser = await _ph.GetBrowserAsync();

        var context = await browser.NewContextAsync();

        await context.RouteAsync("**/*", route =>
        {
            var t = route.Request.ResourceType;
            if (t is "image" or "stylesheet" or "font")
                return route.AbortAsync();
            return route.ContinueAsync();
        });


        var page = await context.NewPageAsync();

        try
        {
            await page.GotoAsync("https://mytax.dc.gov/_/");

            await page.FillAsync("input[name='Dd-9']", model.username);
            await page.FillAsync("input[name='Dd-a']", model.password);

            // simulate clicking or triggering the submit
            await page.ClickAsync("#Dd-b");



            // Wait for the next response or check some indicator
            // Wait for either success or error indicator
            var loginResult = await Task.WhenAny(
                page.WaitForSelectorAsync("text=Invalid user name", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Invalid Username", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Your login details are incorrect", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Username and Password Combination Invalid", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Invalid Login ID", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Verify Security Code", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Two-Step Verification", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Logout", new() { Timeout = 5000 }) // or any valid post-login text
            );

            // Now re-check the DOM safely
            if (await page.IsVisibleAsync("text=Invalid user name") ||
                await page.IsVisibleAsync("text=Invalid Username") ||
                await page.IsVisibleAsync("text=Your login details are incorrect") ||
                await page.IsVisibleAsync("text=Username and Password Combination Invalid") ||
                await page.IsVisibleAsync("text=Invalid Login ID"))
            {
                return new JsonResult(new { success = false, message = "Invalid username or password" });
            }

            if (await page.IsVisibleAsync("text=Verify Security Code") || await page.IsVisibleAsync("text=Two-Step Verification"))
            {
                return new JsonResult(new
                {
                    success = true,
                    message = "Login successful but requires security code verification"
                });
            }
            if (await page.IsVisibleAsync("text=Logout"))
            {
                return new JsonResult(new { success = true, message = "Login successful" });
            }


            return new JsonResult(new { success = false, message = "There is an issue." });

        }
        catch (Exception ex)
        {
            return new JsonResult(new { success = false, message = ex.Message });
        }
    }


    [HttpGet("/KentuckyLogin")]
    public async Task<JsonResult> VerifyKentuckyLogin(LoginModel model)
    {
        // You can also start from https://mytaxes.ky.gov ➜ Log in Now
        return await LoginByBrowserAutomateKentucky(
            model,
            "https://idp-rev.ky.gov/app/kyrev_mytaxes_2/exke25y6ido9fypiO4h7/sso/saml",
            successPoint: "Log Out" // or "Logout" / "MyTaxes Home"
        );
    }
    private async Task<JsonResult> LoginByBrowserAutomateKentucky(LoginModel model, string loginUrl, string successPoint = "Log Out")
    {
        var browser = await _ph.GetBrowserAsync();
        var context = await browser.NewContextAsync();

        // Skip heavy assets
        await context.RouteAsync("**/*", route =>
        {
            var t = route.Request.ResourceType;
            if (t is "image" or "stylesheet" or "font" or "media")
                return route.AbortAsync();
            return route.ContinueAsync();
        });

        var page = await context.NewPageAsync();

        try
        {
            // 1) Open IdP page
            await page.GotoAsync(loginUrl, new() { WaitUntil = WaitUntilState.DOMContentLoaded });

            // Handle occasional interstitials
            if (await page.IsVisibleAsync("text=Cookies are required") || await page.IsVisibleAsync("text=The page has timed out"))
            {
                var refreshBtn = page.Locator("button:has-text('Refresh'), a:has-text('Refresh')");
                if (await refreshBtn.IsVisibleAsync()) await refreshBtn.ClickAsync();
                await page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);
            }

            // 2) Username ➜ Next (best-effort selectors)
            bool filledUser = false;
            try
            {
                await page.GetByLabel("Username", new() { Exact = false }).FillAsync(model.username);
                filledUser = true;
            }
            catch { /* fallbacks below */ }

            if (!filledUser)
            {
                foreach (var sel in new[] { "input[name='username']", "#okta-signin-username", "input[name='userName']", "#idp-discovery-username", "input[type='text']" })
                {
                    if (await page.Locator(sel).First.IsVisibleAsync())
                    {
                        await page.FillAsync(sel, model.username);
                        filledUser = true;
                        break;
                    }
                }
            }
            if (!filledUser)
                return new JsonResult(new { success = false, message = "Username field not found on Kentucky IdP page." });

            // Click Next/Continue if present (some tenants skip this)
            foreach (var nextSel in new[] { "button:has-text('Next')", "#idp-discovery-submit", "input[type='submit'][value='Next']", "button:has-text('Continue')" })
            {
                if (await page.Locator(nextSel).First.IsVisibleAsync())
                {
                    await page.ClickAsync(nextSel);
                    break;
                }
            }

            // -------------------------------
            // 3) WAIT FOR EITHER:
            //    (A) Factor-selection screen, or
            //    (B) Password input field
            // -------------------------------

            // Build both waits (15s total). Do NOT depend on NetworkIdle here.
            var factorTextA = page.WaitForSelectorAsync("text=Verify it's you with a security method", new() { Timeout = 15000 });
            var factorTextB = page.WaitForSelectorAsync("text=Select from the following options", new() { Timeout = 15000 });
            var pwFieldWait = page.WaitForSelectorAsync("input#credentials\\.passcode, input[name='credentials.passcode'], [data-se='credentials.passcode']", new() { Timeout = 15000 });

            var completed = await Task.WhenAny(factorTextA, factorTextB, pwFieldWait);

            // If factor-screen appeared first, click "Password" then wait for the password field.
            if ((completed == factorTextA && factorTextA.Result != null) ||
                (completed == factorTextB && factorTextB.Result != null))
            {
                // Click the Password factor
                var pwBtn = page.GetByRole(AriaRole.Button, new() { Name = "Select Password." })
                    .Or(page.Locator("button[data-se='authenticator-button']", new() { HasText = "Password" }))
                    .Or(page.Locator("button[data-se='authenticator-button']", new() { Has = page.Locator("[data-se='okta_password']") }));

                if (await pwBtn.First.IsVisibleAsync())
                    await pwBtn.First.ClickAsync();
                else
                    return new JsonResult(new { success = false, message = "Password factor button not found." });

                // Now wait specifically for the password field to attach/visible
                await page.WaitForSelectorAsync("input#credentials\\.passcode, input[name='credentials.passcode'], [data-se='credentials.passcode']",
                    new() { Timeout = 15000, State = WaitForSelectorState.Attached });
            }
            else
            {
                // If password field appeared first, we are already on the password page — proceed.
                if (pwFieldWait.Status != TaskStatus.RanToCompletion || pwFieldWait.Result is null)
                {
                    // Neither condition materialized within timeout
                    return new JsonResult(new { success = false, message = "Timed out waiting for factor selection or password field." });
                }
            }

            // 4) Fill password using exact selector(s)
            var pwField = page.Locator("input#credentials\\.passcode")
                .Or(page.Locator("input[name='credentials.passcode']"))
                .Or(page.Locator("[data-se='credentials.passcode']"));

            if (!await pwField.First.IsVisibleAsync(new() { Timeout = 3000 }))
                return new JsonResult(new { success = false, message = "Password field not found on Kentucky IdP page." });

            await pwField.First.FillAsync("");            // clear (if anything there)
            await pwField.First.FillAsync(model.password);

            // Submit
            var submit = page.Locator("button[type='submit']")
                .Or(page.Locator("button:has-text('Verify')"))
                .Or(page.Locator("button:has-text('Sign In')"))
                .Or(page.Locator("button:has-text('Sign in')"));

            if (await submit.First.IsVisibleAsync())
                await submit.First.ClickAsync();
            else
                await pwField.First.PressAsync("Enter");

            // 5) Outcome: invalid creds, MFA, or success
            var outcome = await Task.WhenAny(
                page.WaitForSelectorAsync("text=The username and/or password you entered is incorrect", new() { Timeout = 8000 }),
                page.WaitForSelectorAsync("text=Invalid username or password", new() { Timeout = 8000 }),
                page.WaitForSelectorAsync("text=Account locked", new() { Timeout = 8000 }),
                page.WaitForSelectorAsync("text=Unable to sign in", new() { Timeout = 8000 }),
                page.WaitForSelectorAsync("text=Enter Code", new() { Timeout = 8000 }),
                page.WaitForSelectorAsync("text=Verification code", new() { Timeout = 8000 }),
                page.WaitForSelectorAsync("text=Get a verification email", new() { Timeout = 8000 }),
                page.WaitForSelectorAsync($"text={successPoint}", new() { Timeout = 8000 }),
                page.WaitForSelectorAsync("text=Logout", new() { Timeout = 8000 }),
                page.WaitForURLAsync(new Regex(@"mytaxes\.ky\.gov", RegexOptions.IgnoreCase), new() { Timeout = 8000 })
            );

            // 6) Interpret
            if (await page.IsVisibleAsync("text=The username and/or password you entered is incorrect") ||
                await page.IsVisibleAsync("text=Invalid username or password") ||
                await page.IsVisibleAsync("text=Unable to sign in") ||
                await page.IsVisibleAsync("text=Account locked"))
                return new JsonResult(new { success = false, message = "Invalid username or password." });

            if (await page.IsVisibleAsync("text=Enter Code") || await page.IsVisibleAsync("text=Verification code") || await page.IsVisibleAsync("text=Get a verification email"))
                return new JsonResult(new { success = true, message = "Login successful but requires MFA code verification." });

            if (await page.IsVisibleAsync("text=Logout") ||
                await page.IsVisibleAsync($"text={successPoint}") ||
                page.Url.Contains("mytaxes.ky.gov", StringComparison.OrdinalIgnoreCase))
                return new JsonResult(new { success = true, message = "Login successful." });

            return new JsonResult(new { success = false, message = "Unable to determine login result (unexpected page state)." });
        }
        catch (Exception ex)
        {
            return new JsonResult(new { success = false, message = ex.Message });
        }
    }
    private async Task<JsonResult> VerifyMarylandLogin(LoginModel model)
    {
        var browser = await _ph.GetBrowserAsync();

        var context = await browser.NewContextAsync();

        await context.RouteAsync("**/*", route =>
        {
            var t = route.Request.ResourceType;
            if (t is "image" or "stylesheet" or "font")
                return route.AbortAsync();
            return route.ContinueAsync();
        });


        var page = await context.NewPageAsync();

        try
        {
            await page.GotoAsync("https://mdtaxconnect.gov/rptp/portal/home");

            await page.FillAsync("input[name='userID']", model.username);
            await page.FillAsync("input[name='password']", model.password);

            // simulate clicking or triggering the submit
            await page.ClickAsync("#memberSignInButton");

            var successPoint = "Multi Factor Authentication";


            // Wait for the next response or check some indicator
            // Wait for either success or error indicator
            var loginResult = await Task.WhenAny(
                page.WaitForSelectorAsync("text=Invalid user name", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=The sign in information provided is incorrect", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Invalid Username", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Invalid Login ID", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Verify Security Code", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync($"text={successPoint}", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Logout", new() { Timeout = 5000 }) // or any valid post-login text
            );
            // Now re-check the DOM safely
            if (await page.IsVisibleAsync("text=Invalid user name") ||
                await page.IsVisibleAsync("text=Invalid Username") ||
                await page.IsVisibleAsync("text=The sign in information provided is incorrect") ||
                await page.IsVisibleAsync("text=Invalid Login ID"))
            {
                return new JsonResult(new { success = false, message = "Invalid username or password" });
            }

            if (await page.IsVisibleAsync("text=Verify Security Code") || await page.IsVisibleAsync($"text={successPoint}"))
            {
                return new JsonResult(new
                {
                    success = true,
                    message = "Login successful but requires security code verification"
                });
            }
            if (await page.IsVisibleAsync("text=Logout"))
            {
                return new JsonResult(new { success = true, message = "Login successful" });
            }


            return new JsonResult(new { success = false, message = "There is an issue." });

        }
        catch (Exception ex)
        {
            return new JsonResult(new { success = false, message = ex.Message });
        }
    }

    private async Task<JsonResult> VerifyMichiganLogin(LoginModel model)
    {
        var browser = await _ph.GetBrowserAsync();

        var context = await browser.NewContextAsync();

        await context.RouteAsync("**/*", route =>
        {
            var t = route.Request.ResourceType;
            if (t is "image" or "stylesheet" or "font")
                return route.AbortAsync();
            return route.ContinueAsync();
        });


        var page = await context.NewPageAsync();

        try
        {
            await page.GotoAsync("https://mto.treasury.michigan.gov/eai/mtologin/authenticate?URL=/");

            await page.FillAsync("input[name='userid']", model.username);
            await page.FillAsync("input[name='password']", model.password);

            // simulate clicking or triggering the submit
            await page.ClickAsync("#submit-btn");

            var successPoint = "Welcome to Michigan";


            // Wait for the next response or check some indicator
            // Wait for either success or error indicator
            var loginResult = await Task.WhenAny(
                page.WaitForSelectorAsync("text=Invalid user name", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=The sign in information provided is incorrect", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Invalid Username", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Invalid Login ID", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Verify Security Code", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync($"text={successPoint}", new() { Timeout = 5000 }),
                page.WaitForSelectorAsync("text=Logout", new() { Timeout = 5000 }) // or any valid post-login text
            );
            // Now re-check the DOM safely
            if (await page.IsVisibleAsync("text=Invalid user name") ||
                await page.IsVisibleAsync("text=Invalid Username") ||
                await page.IsVisibleAsync("text=The sign in information provided is incorrect") ||
                await page.IsVisibleAsync("text=Invalid Login ID"))
            {
                return new JsonResult(new { success = false, message = "Invalid username or password" });
            }

            if (await page.IsVisibleAsync("text=Verify Security Code") || await page.IsVisibleAsync($"text={successPoint}"))
            {
                return new JsonResult(new
                {
                    success = true,
                    message = "Login successful but requires security code verification"
                });
            }
            if (await page.IsVisibleAsync("text=Logout"))
            {
                return new JsonResult(new { success = true, message = "Login successful" });
            }


            return new JsonResult(new { success = false, message = "There is an issue." });

        }
        catch (Exception ex)
        {
            return new JsonResult(new { success = false, message = ex.Message });
        }
    }


}


public class LoginModel
{
    public string username { get; set; }
    public string accountNumber { get; set; } = string.Empty;
    public string pin { get; set; } = string.Empty;
    public string password { get; set; }
    public string state { get; set; }
}
