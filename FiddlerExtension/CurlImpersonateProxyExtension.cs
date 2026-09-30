using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using Fiddler;
using static System.Net.Mime.MediaTypeNames;

namespace FiddlerCurlImpersonateProxy
{
    public sealed class CurlImpersonateProxyExtension : IAutoTamper3
    {
        private const string PrefPrefix = "extensions.curl-impersonate-proxy.";
        private const string OriginalMethod = "x-impersonate-original-method";
        private const string OriginalScheme = "x-impersonate-original-scheme";
        private const string UpstreamHttpFlag = "x-impersonate-upstream-http";
        private const string ExtensionFlag = "x-impersonate-extension";
        private const string ShowUrlHideReason = "Impersonate Show URL filter";

        private volatile bool _enabled;
        private volatile string _profile;
        private volatile string _httpVersion;
        private volatile int _workers;
        private volatile int _proxyPort;
        private volatile bool _showConsole;
        private volatile string _showUrlFilter;
        private readonly object _processSync = new object();
        private readonly ConcurrentDictionary<int, Session> _showUrlHiddenSessions =
            new ConcurrentDictionary<int, Session>();
        private Process _ownedProxyProcess;
        private MenuItem _rootMenu;
        private MenuItem _enabledMenu;
        private MenuItem _workersMenu;
        private MenuItem _consoleMenu;
        private MenuItem _startProxyMenu;
        private MenuItem _stopProxyMenu;
        private MenuItem _proxyStatusMenu;
        private MenuItem _copyTestMenu;
        private MenuItem _filterTestMenu;
        private MenuItem _filterNowMenu;
        private object _filterNowView;
        private string _showUrlFilterLabel;
        private EventInfo _removeFilterEvent;
        private Delegate _removeFilterHandler;


        private static bool IsImpersonateSession(Session session)
        {
            return session != null && session[ExtensionFlag] == "1";
        }

        private bool IsImpersonateExt(Session session)
        {
            return _enabled && IsImpersonateSession(session);
        }

        private static void SetIsImpersonateSession(Session session)
        {
            if (session != null)
                session[ExtensionFlag] = "1";
        }

        private static bool IsLocal(Session session)
        {
            return Regex.IsMatch(session.hostname, @"^(?:localhost|::1|127(?:\.\d{1,3}){3}|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})$", RegexOptions.IgnoreCase);
        }


        public void OnLoad()
        {
            LoadPreferences();
            FiddlerApplication.AfterSessionComplete += OnAfterSessionComplete;
            AddMenu();
            AddSessionContextMenuItems();
            InitializeFilterNowView();

            if (_enabled)
            {
                EnsureProxyRunning();
            }
            UpdateProxyStatus();

            FiddlerApplication.Log.LogString("Curl Impersonate Proxy Extension 1.0 loaded.");
        }

        public void OnBeforeUnload()
        {
            FiddlerApplication.AfterSessionComplete -= OnAfterSessionComplete;
            RemoveFilterNowViewHandler();
            RemoveSessionContextMenuItems();
            StopProxy(false);
        }

        public void OnPeekAtRequestHeaders(Session session)
        {
        }

        public void AutoTamperRequestBefore(Session session)
        {
            if (!_enabled)
            {
                return;
            }

            if (session.HTTPMethodIs("CONNECT"))
            {
                if (IsLocal(session))
                {
                    session["x-no-decrypt"] = "Curl Impersonate Proxy";
                }
                else
                {
                    session["x-replywithtunnel"] = "Curl Impersonate Proxy synthetic tunnel";
                }
            }
            else
            {
                ApplyShowUrlFilter(session);
            }
        }

        public void AutoTamperRequestAfter(Session session)
        {
            if (!_enabled || ShouldSkip(session))
            {
                return;
            }
            if (!IsOwnedProxyRunning() && !EnsureProxyRunning())
            {
                return;
            }

            SetIsImpersonateSession(session);



            bool IsHttps = session.isHTTPS;
            string method = session.oRequest.headers.HTTPMethod;
            

            if (IsHttps)
                session.oRequest.headers.HTTPMethod = "\u0001" + method;
          
            session[OriginalMethod] = method;
            session[OriginalScheme] = IsHttps ? "https" : "http";
            session["x-overrideHost"] = "127.0.0.1:" + _proxyPort;

            session.bypassGateway = true;
            session.oRequest.headers.UriScheme = "http";

        }
 

        public void OnPeekAtResponseHeaders(Session session)
        {
            if (!IsImpersonateExt(session)) return;

            session.bBufferResponse = true;
            if (session.oResponse != null && session.oResponse.headers.Exists("X-Proxy-Upstream-Http"))
            {
                session[UpstreamHttpFlag] = session.oResponse.headers["X-Proxy-Upstream-Http"];
            }
            RemoveProxyResponseHeaders(session);
            RestoreOriginalRequest(session);
            RemoveProxyRequestHeaders(session);
        }

        public void AutoTamperResponseBefore(Session session)
        {
            if (IsImpersonateExt(session))
                session.utilDecodeResponse();
        }

        public void AutoTamperResponseAfter(Session session)
        {
        }

        private static void OnAfterSessionComplete(Session session)
        {
            ApplyUpstreamProtocolForDisplay(session);
        }

        public void OnBeforeReturningError(Session session)
        {
            if (IsImpersonateExt(session))
                RestoreOriginalRequest(session);
        }

        private static void RestoreOriginalRequest(Session session)
        {
            String method = session[OriginalMethod];
            if (!String.IsNullOrEmpty(method))
                session.oRequest.headers.HTTPMethod = method;

            String scheme = session[OriginalScheme];
            if (!String.IsNullOrEmpty(scheme))
                session.oRequest.headers.UriScheme = scheme;
        }

        private bool ShouldSkip(Session session)
        {

            if (IsImpersonateSession(session))
                return true;

            if (session.HTTPMethodIs("CONNECT") || session.isFlagSet(SessionFlags.ResponseGeneratedByFiddler))
                return true;


            if (session.oRequest.headers.Exists("Upgrade"))
                return true;

            if (IsLocal(session))
                return true;

               

            return false;
        }


        private static void RemoveProxyRequestHeaders(Session session)
        {
            session["x-overrideHost"] = null;
        }

        private static void RemoveProxyResponseHeaders(Session session)
        {
            session.oResponse.headers.Remove("X-Proxy-Upstream-Http");
            session.oResponse.headers.Remove("X-Proxy-Decoded-Content-Encoding");
        }

        private static void ApplyUpstreamProtocolForDisplay(Session session)
        {
            if (!IsImpersonateSession(session) || session.oResponse == null)
            {
                return;
            }

            string upstreamHttp = session[UpstreamHttpFlag];
            if (string.Equals(upstreamHttp, "h3", StringComparison.OrdinalIgnoreCase))
            {
                session.oResponse.headers.HTTPVersion = "HTTP/3";
            }
            else if (string.Equals(upstreamHttp, "h2", StringComparison.OrdinalIgnoreCase))
            {
                session.oResponse.headers.HTTPVersion = "HTTP/2";
            }
            else if (string.Equals(upstreamHttp, "http/1.0", StringComparison.OrdinalIgnoreCase))
            {
                session.oResponse.headers.HTTPVersion = "HTTP/1.0";
            }
            else if (string.Equals(upstreamHttp, "http/1.1", StringComparison.OrdinalIgnoreCase))
            {
                session.oResponse.headers.HTTPVersion = "HTTP/1.1";
            }
        }

   
        private void LoadPreferences()
        {
            _enabled = FiddlerApplication.Prefs.GetBoolPref(PrefPrefix + "enabled", true);
            _profile = FiddlerApplication.Prefs.GetStringPref(PrefPrefix + "profile", "chrome150");
            _httpVersion = FiddlerApplication.Prefs.GetStringPref(PrefPrefix + "http-version", "auto");
            _workers = FiddlerApplication.Prefs.GetInt32Pref(PrefPrefix + "workers", 32);
            _showConsole = FiddlerApplication.Prefs.GetBoolPref(PrefPrefix + "show-console", false);
            _showUrlFilter = FiddlerApplication.Prefs.GetStringPref(PrefPrefix + "show-url-filter", "");
            if (_workers < 1 || _workers > 256)
            {
                _workers = 32;
            }
        }

        private void AddMenu()
        {
            _rootMenu = new MenuItem("&Curl Impersonate Proxy");

            _enabledMenu = new MenuItem("&Enabled", delegate
            {
                _enabled = !_enabled;
                _enabledMenu.Checked = _enabled;
                FiddlerApplication.Prefs.SetBoolPref(PrefPrefix + "enabled", _enabled);
                if (_enabled)
                {
                    EnsureProxyRunning();
                }
                else
                {
                    StopProxy(false);
                }
                UpdateProxyStatus();
            });
            _enabledMenu.Checked = _enabled;
            _rootMenu.MenuItems.Add(_enabledMenu);

            MenuItem profileMenu = new MenuItem("Browser &profile");
            AddChoice(profileMenu, "Chrome 150", "chrome150", SetProfile, delegate { return _profile; });

            AddChoice(profileMenu, "Firefox 147", "firefox147", SetProfile, delegate { return _profile; });
            AddChoice(profileMenu, "Safari 26.0.1", "safari2601", SetProfile, delegate { return _profile; });
            AddChoice(profileMenu, "Android 14", "chrome131_android", SetProfile, delegate { return _profile; });

            MenuItem manualProfile = new MenuItem("Other / manual input...");
            manualProfile.RadioCheck = true;
            manualProfile.Checked = !IsBuiltInProfile(_profile);
            manualProfile.Click += delegate
            {
                string profile;
                if (!ShowProfileDialog(out profile))
                {
                    return;
                }

                SetProfile(profile);
                foreach (MenuItem sibling in profileMenu.MenuItems)
                {
                    sibling.Checked = false;
                }
                manualProfile.Checked = true;
            };
            profileMenu.MenuItems.Add(manualProfile);
            _rootMenu.MenuItems.Add(profileMenu);

            MenuItem httpMenu = new MenuItem("Upstream &HTTP");
            AddChoice(httpMenu, "HTTP/3 with fallback", "auto", SetHttpVersion,
                      delegate { return _httpVersion; });
            AddChoice(httpMenu, "HTTP/2", "2", SetHttpVersion, delegate { return _httpVersion; });
            AddChoice(httpMenu, "HTTP/3 only", "3", SetHttpVersion,
                      delegate { return _httpVersion; });
            _rootMenu.MenuItems.Add(httpMenu);

            _workersMenu = new MenuItem();
            _workersMenu.Click += delegate { ShowWorkersDialog(); };
            UpdateWorkersMenu();
            _rootMenu.MenuItems.Add(_workersMenu);

            _consoleMenu = new MenuItem();
            _consoleMenu.Click += delegate
            {
                _showConsole = !_showConsole;
                FiddlerApplication.Prefs.SetBoolPref(PrefPrefix + "show-console", _showConsole);
                UpdateConsoleMenu();
                RestartProxyForConfigChange();
            };
            UpdateConsoleMenu();
            _rootMenu.MenuItems.Add(_consoleMenu);
            _rootMenu.MenuItems.Add("-");

            _startProxyMenu = new MenuItem("Start proxy", delegate
            {
                _enabled = true;
                _enabledMenu.Checked = true;
                FiddlerApplication.Prefs.SetBoolPref(PrefPrefix + "enabled", true);
                EnsureProxyRunning();
                UpdateProxyStatus();
            });
            _rootMenu.MenuItems.Add(_startProxyMenu);

            _stopProxyMenu = new MenuItem("Stop proxy", delegate
            {
                StopProxy(true);
                UpdateProxyStatus();
            });
            _rootMenu.MenuItems.Add(_stopProxyMenu);

            _proxyStatusMenu = new MenuItem();
            _proxyStatusMenu.Enabled = false;
            _rootMenu.MenuItems.Add(_proxyStatusMenu);
            UpdateProxyStatus();

            FiddlerApplication.UI.mnuRules.MenuItems.Add(_rootMenu);
        }

        private static void AddChoice(MenuItem parent, string label, string value,
                                      Action<string> setter, Func<string> getter)
        {
            MenuItem item = new MenuItem(label);
            item.RadioCheck = true;
            item.Click += delegate
            {
                setter(value);
                foreach (MenuItem sibling in parent.MenuItems)
                {
                    sibling.Checked = false;
                }
                item.Checked = true;
            };
            item.Checked = string.Equals(getter(), value, StringComparison.OrdinalIgnoreCase);
            parent.MenuItems.Add(item);
        }


        private void FilterSessionsByUrl()
        {
            string result = FiddlerObject.prompt(
                "Show all Sessions whose Url contains...",
                FiddlerApplication.UI.GetFirstSelectedSession().host,
                "[Impersonate Patch] Show sessions with Url..."
            );

            if (String.IsNullOrEmpty(result))
                return;

            FiddlerApplication.UI.lvSessions.BeginUpdate();
            try
            {
                ClearShowUrlFilter(true);
                _showUrlFilter = result;
                FiddlerApplication.Prefs.SetStringPref(PrefPrefix + "show-url-filter", result);
                AddShowUrlFilterLabel();

                foreach (Session session in FiddlerApplication.UI.GetAllSessions())
                {
                    ApplyShowUrlFilter(session);
                    session.RefreshUI();
                }
            }
            finally
            {
                FiddlerApplication.UI.lvSessions.EndUpdate();
            }
        }

        private void ApplyShowUrlFilter(Session session)
        {
            if (String.IsNullOrEmpty(_showUrlFilter))
            {
                return;
            }

            if (session.fullUrl.IndexOf(_showUrlFilter, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return;
            }

            session["ui-hide"] = ShowUrlHideReason;
            _showUrlHiddenSessions[session.id] = session;
        }

        private void InitializeFilterNowView()
        {
            FieldInfo presenterField = FiddlerApplication.UI.GetType().GetField(
                "publisherComposer",
                BindingFlags.Instance | BindingFlags.NonPublic
            );
            object presenter = presenterField.GetValue(FiddlerApplication.UI);
            FieldInfo viewField = presenter.GetType().GetField(
                "_RepositoryState",
                BindingFlags.Instance | BindingFlags.NonPublic
            );
            _filterNowView = viewField.GetValue(presenter);

            _removeFilterEvent = _filterNowView.GetType().GetEvent("RemoveFilterClicked");
            MethodInfo handlerMethod = GetType().GetMethod(
                "OnFilterNowRemoveClicked",
                BindingFlags.Instance | BindingFlags.NonPublic
            );
            _removeFilterHandler = Delegate.CreateDelegate(
                _removeFilterEvent.EventHandlerType,
                this,
                handlerMethod
            );
            _removeFilterEvent.AddEventHandler(_filterNowView, _removeFilterHandler);
            AddShowUrlFilterLabel();
        }

        private void OnFilterNowRemoveClicked(object sender, EventArgs eventArgs)
        {
            string label = (string)eventArgs.GetType().GetProperty("Text").GetValue(
                eventArgs,
                null
            );
            if (!String.Equals(label, _showUrlFilterLabel, StringComparison.Ordinal))
            {
                return;
            }

            _showUrlFilterLabel = null;
            _filterNowView.GetType().GetMethod("RemoveFilter").Invoke(
                _filterNowView,
                new object[] { label }
            );
            ClearShowUrlFilter(false);
        }

        private void ClearShowUrlFilter(bool removeLabel)
        {
            if (removeLabel)
            {
                RemoveShowUrlFilterLabel();
            }

            _showUrlFilter = String.Empty;
            FiddlerApplication.Prefs.RemovePref(PrefPrefix + "show-url-filter");

            foreach (Session session in _showUrlHiddenSessions.Values)
            {
                if (String.Equals(session["ui-hide"], ShowUrlHideReason, StringComparison.Ordinal))
                {
                    session.oFlags.Remove("ui-hide");
                    FiddlerApplication.UI.addSession(session);
                    session.RefreshUI();
                }
            }
            _showUrlHiddenSessions.Clear();
        }

        private void RemoveFilterNowViewHandler()
        {
            _removeFilterEvent.RemoveEventHandler(_filterNowView, _removeFilterHandler);
            _removeFilterHandler = null;
            _removeFilterEvent = null;
        }

        private void AddShowUrlFilterLabel()
        {
            if (String.IsNullOrEmpty(_showUrlFilter))
            {
                return;
            }

            _showUrlFilterLabel = "Show '" + _showUrlFilter + "'";
            _filterNowView.GetType().GetMethod("AddFilter").Invoke(
                _filterNowView,
                new object[] { _showUrlFilterLabel }
            );
        }

        private void RemoveShowUrlFilterLabel()
        {
            if (String.IsNullOrEmpty(_showUrlFilterLabel))
            {
                return;
            }

            string label = _showUrlFilterLabel;
            _showUrlFilterLabel = null;
            _filterNowView.GetType().GetMethod("RemoveFilter").Invoke(
                _filterNowView,
                new object[] { label }
            );
        }

        private void AddSessionContextMenuItems()
        {
            _copyTestMenu = new MenuItem("Test", delegate { });
            FiddlerApplication.UI.miSessionCopy.MenuItems.Add(_copyTestMenu);


            foreach (MenuItem item in FiddlerApplication.UI.miSessionCopy.Parent.MenuItems)
            {
                string text = item.Text.Replace("&", string.Empty);


                if (text.StartsWith("Filter Now", StringComparison.OrdinalIgnoreCase))
                {
                    _filterNowMenu = item;
                    break;
                }
            }

            if (_filterNowMenu != null)
            {
                _filterTestMenu = new MenuItem("Show URL containing...", delegate { FilterSessionsByUrl(); });
                _filterNowMenu.Popup += OnFilterNowMenuPopup;

                FiddlerApplication.Log.LogString("added");
            }
        }

        private void OnFilterNowMenuPopup(object sender, EventArgs e)
        {

 

            if (_filterTestMenu.Parent != _filterNowMenu)
            {
                _filterNowMenu.MenuItems.Add(_filterTestMenu);
            }
        }

        private void RemoveSessionContextMenuItems()
        {
            if (_copyTestMenu != null)
            {
                FiddlerApplication.UI.miSessionCopy.MenuItems.Remove(_copyTestMenu);
                _copyTestMenu.Dispose();
                _copyTestMenu = null;
            }

            if (_filterTestMenu != null)
            {
                _filterNowMenu.Popup -= OnFilterNowMenuPopup;
                if (_filterTestMenu.Parent == _filterNowMenu)
                {
                    _filterNowMenu.MenuItems.Remove(_filterTestMenu);
                }
                _filterTestMenu.Dispose();
                _filterTestMenu = null;
                _filterNowMenu = null;
            }
        }

        private void SetProfile(string value)
        {
            if (string.Equals(_profile, value, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
            _profile = value;
            FiddlerApplication.Prefs.SetStringPref(PrefPrefix + "profile", value);
            RestartProxyForConfigChange();
        }

        private void SetHttpVersion(string value)
        {
            if (string.Equals(_httpVersion, value, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
            _httpVersion = value;
            FiddlerApplication.Prefs.SetStringPref(PrefPrefix + "http-version", value);
            RestartProxyForConfigChange();
        }

        private void RestartProxyForConfigChange()
        {
            if (!_enabled || !IsOwnedProxyRunning())
            {
                return;
            }
            StopProxy(false);
            EnsureProxyRunning();
            UpdateProxyStatus();
        }

        private static bool IsBuiltInProfile(string profile)
        {
            return string.Equals(profile, "chrome150", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(profile, "firefox147", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(profile, "safari2601", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(profile, "chrome131_android", StringComparison.OrdinalIgnoreCase);
        }

        private bool EnsureProxyRunning()
        {
            if (!_enabled)
            {
                return false;
            }
            lock (_processSync)
            {
                if (IsOwnedProxyRunning() && IsProxyListening(_proxyPort))
                {
                    return true;
                }

                DisposeExitedProxy();

                string extensionDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                string proxyDirectory = Path.Combine(extensionDirectory, "CurlImpersonateProxyExtension");
                string proxyPath = Path.Combine(proxyDirectory, "fiddler-impersonate-proxy.exe");
                if (!File.Exists(proxyPath))
                {
                    FiddlerApplication.Log.LogString("Curl Impersonate Proxy executable not found: " + proxyPath);
                    return false;
                }

                _proxyPort = FindAvailablePort();
                ProcessStartInfo startInfo = new ProcessStartInfo(proxyPath,
                    "--port " + _proxyPort + " --profile " + _profile + " --http " + _httpVersion +
                    " --workers " + _workers);
                startInfo.WorkingDirectory = proxyDirectory;
                startInfo.UseShellExecute = _showConsole;
                startInfo.CreateNoWindow = !_showConsole;
                startInfo.WindowStyle = _showConsole
                    ? ProcessWindowStyle.Normal
                    : ProcessWindowStyle.Hidden;

                try
                {
                    _ownedProxyProcess = Process.Start(startInfo);
                    for (int attempt = 0; attempt < 40; ++attempt)
                    {
                        if (_ownedProxyProcess.HasExited)
                        {
                            break;
                        }
                        if (IsProxyListening(_proxyPort))
                        {
                            FiddlerApplication.Log.LogString(
                                "Curl Impersonate Proxy started on 127.0.0.1:" + _proxyPort +
                                " with " + _workers + " workers.");
                            return true;
                        }
                        Thread.Sleep(50);
                    }
                }
                catch (Exception error)
                {
                    FiddlerApplication.Log.LogString("Curl Impersonate Proxy failed to start: " + error.Message);
                }

                StopProxyProcess();
                FiddlerApplication.Log.LogString("Curl Impersonate Proxy did not become ready.");
                return false;
            }
        }

        private void UpdateProxyStatus()
        {
            bool running = IsOwnedProxyRunning() && IsProxyListening(_proxyPort);
            if (_startProxyMenu != null)
            {
                _startProxyMenu.Enabled = !running;
            }
            if (_stopProxyMenu != null)
            {
                _stopProxyMenu.Enabled = running;
            }
            if (_proxyStatusMenu != null)
            {
                _proxyStatusMenu.Text = running
                    ? "Proxy: running on 127.0.0.1:" + _proxyPort
                    : "Proxy: stopped";
            }
        }

        private static bool IsProxyListening(int port)
        {
            if (port < 1)
            {
                return false;
            }
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    IAsyncResult result = client.BeginConnect("127.0.0.1", port, null, null);
                    bool connected = result.AsyncWaitHandle.WaitOne(250);
                    if (connected)
                    {
                        client.EndConnect(result);
                    }
                    return connected;
                }
            }
            catch (SocketException)
            {
                return false;
            }
        }

        private bool IsOwnedProxyRunning()
        {
            try
            {
                return _ownedProxyProcess != null && !_ownedProxyProcess.HasExited;
            }
            catch (InvalidOperationException)
            {
                return false;
            }
        }

        private static int FindAvailablePort()
        {
            TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }

        private void StopProxy(bool disableRouting)
        {
            lock (_processSync)
            {
                StopProxyProcess();
            }
            if (disableRouting)
            {
                _enabled = false;
                _enabledMenu.Checked = false;
                FiddlerApplication.Prefs.SetBoolPref(PrefPrefix + "enabled", false);
            }
        }

        private void StopProxyProcess()
        {
            try
            {
                if (_ownedProxyProcess != null && !_ownedProxyProcess.HasExited)
                {
                    _ownedProxyProcess.Kill();
                    _ownedProxyProcess.WaitForExit(2000);
                }
            }
            catch (InvalidOperationException)
            {
            }
            catch (System.ComponentModel.Win32Exception error)
            {
                FiddlerApplication.Log.LogString("Curl Impersonate Proxy failed to stop: " + error.Message);
            }
            finally
            {
                if (_ownedProxyProcess != null)
                {
                    _ownedProxyProcess.Dispose();
                    _ownedProxyProcess = null;
                }
                _proxyPort = 0;
            }
        }

        private void DisposeExitedProxy()
        {
            if (_ownedProxyProcess != null && _ownedProxyProcess.HasExited)
            {
                _ownedProxyProcess.Dispose();
                _ownedProxyProcess = null;
                _proxyPort = 0;
            }
        }

        private bool ShowProfileDialog(out string profile)
        {
            profile = null;
            using (Form dialog = new Form())
            using (TextBox profileField = new TextBox())
            using (Button saveButton = new Button())
            using (Button cancelButton = new Button())
            {
                dialog.Text = "Browser profile";
                dialog.FormBorderStyle = FormBorderStyle.FixedDialog;
                dialog.StartPosition = FormStartPosition.CenterParent;
                dialog.ClientSize = new System.Drawing.Size(390, 105);
                dialog.MaximizeBox = false;
                dialog.MinimizeBox = false;
                dialog.ShowInTaskbar = false;

                Label label = new Label();
                label.Text = "Impersonation profile name:";
                label.AutoSize = true;
                label.Location = new System.Drawing.Point(12, 17);
                dialog.Controls.Add(label);

                profileField.Text = _profile;
                profileField.Location = new System.Drawing.Point(165, 14);
                profileField.Size = new System.Drawing.Size(210, 20);
                dialog.Controls.Add(profileField);

                saveButton.Text = "Apply";
                saveButton.DialogResult = DialogResult.OK;
                saveButton.Location = new System.Drawing.Point(219, 57);
                dialog.Controls.Add(saveButton);

                cancelButton.Text = "Cancel";
                cancelButton.DialogResult = DialogResult.Cancel;
                cancelButton.Location = new System.Drawing.Point(300, 57);
                dialog.Controls.Add(cancelButton);

                dialog.AcceptButton = saveButton;
                dialog.CancelButton = cancelButton;
                if (dialog.ShowDialog(FiddlerApplication.UI) != DialogResult.OK)
                {
                    return false;
                }

                profile = profileField.Text.Trim();
                return profile.Length > 0;
            }
        }

        private void ShowWorkersDialog()
        {
            using (Form dialog = new Form())
            using (NumericUpDown workersField = new NumericUpDown())
            using (Button saveButton = new Button())
            using (Button cancelButton = new Button())
            {
                dialog.Text = "Proxy workers";
                dialog.FormBorderStyle = FormBorderStyle.FixedDialog;
                dialog.StartPosition = FormStartPosition.CenterParent;
                dialog.ClientSize = new System.Drawing.Size(280, 92);
                dialog.MaximizeBox = false;
                dialog.MinimizeBox = false;
                dialog.ShowInTaskbar = false;

                Label label = new Label();
                label.Text = "Concurrent workers:";
                label.AutoSize = true;
                label.Location = new System.Drawing.Point(12, 17);
                dialog.Controls.Add(label);

                workersField.Minimum = 1;
                workersField.Maximum = 256;
                workersField.Value = _workers;
                workersField.Location = new System.Drawing.Point(154, 14);
                workersField.Size = new System.Drawing.Size(110, 20);
                dialog.Controls.Add(workersField);

                saveButton.Text = "Apply";
                saveButton.DialogResult = DialogResult.OK;
                saveButton.Location = new System.Drawing.Point(108, 52);
                dialog.Controls.Add(saveButton);

                cancelButton.Text = "Cancel";
                cancelButton.DialogResult = DialogResult.Cancel;
                cancelButton.Location = new System.Drawing.Point(189, 52);
                dialog.Controls.Add(cancelButton);

                dialog.AcceptButton = saveButton;
                dialog.CancelButton = cancelButton;
                if (dialog.ShowDialog(FiddlerApplication.UI) != DialogResult.OK)
                {
                    return;
                }

                _workers = Decimal.ToInt32(workersField.Value);
                FiddlerApplication.Prefs.SetInt32Pref(PrefPrefix + "workers", _workers);
                UpdateWorkersMenu();
                RestartProxyForConfigChange();
            }
        }

        private void UpdateWorkersMenu()
        {
            _workersMenu.Text = "Proxy workers: " + _workers + "...";
        }

        private void UpdateConsoleMenu()
        {
            _consoleMenu.Text = _showConsole ? "Hide console" : "Show console";
        }

    }
}
