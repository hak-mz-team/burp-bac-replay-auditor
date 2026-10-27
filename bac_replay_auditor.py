

from burp import IBurpExtender, ITab, IProxyListener

from java.util import ArrayList
from java.util.concurrent import ConcurrentHashMap
from javax.swing import (
    JPanel, JLabel, JTextField, JButton, JCheckBox, JTable, JScrollPane,
    SwingUtilities, BorderFactory, JPopupMenu, JMenuItem, JComponent,
    KeyStroke, AbstractAction, ListSelectionModel, RowFilter
)
from javax.swing.table import DefaultTableModel, TableRowSorter, DefaultTableCellRenderer
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Toolkit, Color
from java.lang import Object
from java.awt.datatransfer import StringSelection
from java.awt.event import ActionListener, MouseAdapter, KeyEvent, InputEvent
from java.lang import Runnable
import threading
import Queue
import json
import time
from java.lang import String

EXTENSION_NAME = "BAC Replay Auditor (Jython)"
MARKER_HEADER = "X-BAC-Extension"
COLOR_HEADER = "X-PwnFox-Color"

class ReadOnlyTableModel(DefaultTableModel):
    def isCellEditable(self, row, column):
        return False

class PendingRecord(object):
    def __init__(self, method, endpoint):
        self.method = method
        self.endpoint = endpoint
        self.created_at = time.time()
        self.admin_status = None
        self.low_status = None
        self.admin_length = None
        self.low_length = None
        self.forced_analysis = None
        self.complete = False
        self.lock = threading.RLock()

class BurpExtender(IBurpExtender, ITab, IProxyListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName(EXTENSION_NAME)

        self.low_cookie_by_host = ConcurrentHashMap()
        self.low_headers_by_host = ConcurrentHashMap()
        self.low_params_by_host = ConcurrentHashMap()
        self.header_cache_lock = threading.RLock()
        self.pending_by_ref = ConcurrentHashMap()
        self.work_queue = Queue.Queue(250)
        self.queue_workers = []
        self.worker_target_count = 4
        self.max_worker_count = 8
        self.stalled_worker_seconds = 45
        self._worker_lock = threading.RLock()
        self._worker_seq = 0
        self._active_worker_lock = threading.RLock()
        self._active_worker_since = {}
        self.max_pending = 250
        self.pending_ttl_seconds = 120
        self._diagnostic_lock = threading.RLock()
        self._diagnostics_emitted = set()

        if SwingUtilities.isEventDispatchThread():
            self._build_ui()
        else:
            SwingUtilities.invokeAndWait(_BuildUiRunnable(self))
        callbacks.addSuiteTab(self)
        callbacks.registerProxyListener(self)
        self._start_workers(self.worker_target_count)

        callbacks.printOutput("%s loaded. Replay is OFF by default." % EXTENSION_NAME)
        callbacks.printOutput(
            "Add the authorized target to Burp Target scope, set admin/low colors, and browse "
            "with the low-privilege session. Cookie replacement is optional when no low-priv "
            "Cookie exists; configured headers and parameters can supply replacement values."
        )

    def _build_ui(self):
        self.main_panel = JPanel(BorderLayout(8, 8))
        self.main_panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        config = JPanel(GridBagLayout())
        config.setBorder(BorderFactory.createTitledBorder("Configuration"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(3, 4, 3, 4)
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 0.0

        self.target_host_field = JTextField("target.com", 28)
        self.low_color_field = JTextField("cyan", 10)
        self.admin_color_field = JTextField("magenta", 10)
        self.exclude_field = JTextField(".js, .css, .png, logout", 28)
        self.enable_box = JCheckBox("Enable replay (GET/HEAD)", False)
        self.allow_write_box = JCheckBox(
            "Also replay POST/PUT/PATCH/DELETE (may change server state)", False
        )
        self.hide_4xx_box = JCheckBox("Hide low-priv 4xx responses (400-499)", False)
        self.replace_headers_field = JTextField(
            "Authorization, X-API-Key, X-Auth-Token, X-Access-Token", 52
        )
        self.keep_admin_headers_field = JTextField("", 52)
        self.replace_parameters_field = JTextField("", 52)
        self.replace_headers_field.setToolTipText(
            "Comma-separated headers copied from the low-priv session. Cookie is replaced when a low-priv Cookie is cached; otherwise the admin Cookie is removed. "
            "If a listed header exists on the admin request but no low-priv value was captured, "
            "the admin value is removed. Browse with the low-priv session after changing this list."
        )
        self.keep_admin_headers_field.setToolTipText(
            "Preserves original values only for normally stripped sensitive headers (Authorization, API keys, etc.). "
            "Use sparingly to avoid false positives. A header in the replace list is replaced instead. "
            "Other non-authentication headers are kept automatically."
        )
        self.replace_parameters_field.setToolTipText(
            "Comma-separated parameter names to replace using values captured from the low-privilege session. "
            "Supports URL query, form-urlencoded body, and JSON parameters. Match is case-insensitive. "
            "If no low-privilege value was captured for a configured parameter, the admin value is removed."
        )
        self.copy_rows_button = JButton("Copy Selected Row(s)")
        self.clear_button = JButton("Clear Results")
        self.capture_status_label = JLabel(
            "PwnFox capture status: waiting for a low-privilege request in Burp Target scope."
        )
        self.cache_status_label = JLabel("Low-priv auth cache: empty (browse with the low-privilege session)")

        self._add_config_row(config, gbc, 0, "Target Host", self.target_host_field,
                             "Low-Priv Pwnfox Color", self.low_color_field)
        self._add_config_row(config, gbc, 1, "Admin Pwnfox Color", self.admin_color_field,
                             "Exclude Paths", self.exclude_field)

        gbc.gridx = 0
        gbc.gridy = 2
        gbc.gridwidth = 1
        gbc.weightx = 0.0
        config.add(JLabel("Replace with low-priv headers:"), gbc)
        gbc.gridx = 1
        gbc.gridwidth = 3
        gbc.weightx = 1.0
        config.add(self.replace_headers_field, gbc)

        gbc.gridx = 0
        gbc.gridy = 3
        gbc.gridwidth = 1
        gbc.weightx = 0.0
        config.add(JLabel("Keep original admin headers:"), gbc)
        gbc.gridx = 1
        gbc.gridwidth = 3
        gbc.weightx = 1.0
        config.add(self.keep_admin_headers_field, gbc)

        gbc.gridx = 0
        gbc.gridy = 4
        gbc.gridwidth = 1
        gbc.weightx = 0.0
        config.add(JLabel("Replace parameter values:"), gbc)
        gbc.gridx = 1
        gbc.gridwidth = 3
        gbc.weightx = 1.0
        config.add(self.replace_parameters_field, gbc)

        gbc.gridx = 0
        gbc.gridy = 5
        gbc.gridwidth = 2
        gbc.weightx = 1.0
        config.add(self.enable_box, gbc)
        gbc.gridx = 2
        gbc.gridwidth = 1
        gbc.weightx = 0.0
        config.add(self.copy_rows_button, gbc)
        gbc.gridx = 3
        gbc.gridwidth = 1
        config.add(self.clear_button, gbc)

        gbc.gridx = 0
        gbc.gridy = 6
        gbc.gridwidth = 4
        gbc.weightx = 1.0
        config.add(self.allow_write_box, gbc)

        gbc.gridx = 0
        gbc.gridy = 7
        gbc.gridwidth = 4
        config.add(self.hide_4xx_box, gbc)

        gbc.gridx = 0
        gbc.gridy = 8
        gbc.gridwidth = 4
        config.add(self.cache_status_label, gbc)

        gbc.gridx = 0
        gbc.gridy = 9
        gbc.gridwidth = 4
        config.add(self.capture_status_label, gbc)

        self.table_model = ReadOnlyTableModel(
            ["Method", "Endpoint", "Admin Status", "Low-Priv Status", "Admin Body Length (B)", "Low-Priv Body Length (B)", "Result Analysis"], 0
        )
        self.results_table = JTable(self.table_model)

        self.table_sorter = TableRowSorter(self.table_model)
        self.results_table.setRowSorter(self.table_sorter)

        self.results_table.setDefaultRenderer(Object, _BacRowRenderer(self))
        self.results_table.setFillsViewportHeight(True)
        self.results_table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        self.results_table.setCellSelectionEnabled(True)
        self.results_table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)

        copy_key = KeyStroke.getKeyStroke(KeyEvent.VK_C, InputEvent.CTRL_DOWN_MASK)
        self.results_table.getInputMap(JComponent.WHEN_FOCUSED).put(copy_key, "bac-copy-cells")
        self.results_table.getActionMap().put("bac-copy-cells", _CopyCellsAction(self))

        popup = JPopupMenu()
        copy_cells_item = JMenuItem("Copy selected cell(s)")
        copy_rows_item = JMenuItem("Copy selected row(s)")
        copy_cells_item.addActionListener(_CopyCellsButtonListener(self))
        copy_rows_item.addActionListener(_CopyRowsButtonListener(self))
        popup.add(copy_cells_item)
        popup.add(copy_rows_item)
        self.results_table.setComponentPopupMenu(popup)
        self.results_table.addMouseListener(_SelectCellOnPopupListener(self))
        self.results_table.getColumnModel().getColumn(0).setPreferredWidth(70)
        self.results_table.getColumnModel().getColumn(1).setPreferredWidth(620)
        self.results_table.getColumnModel().getColumn(2).setPreferredWidth(100)
        self.results_table.getColumnModel().getColumn(3).setPreferredWidth(120)
        self.results_table.getColumnModel().getColumn(4).setPreferredWidth(145)
        self.results_table.getColumnModel().getColumn(5).setPreferredWidth(155)
        self.results_table.getColumnModel().getColumn(6).setPreferredWidth(280)

        self.main_panel.add(config, BorderLayout.NORTH)
        self.main_panel.add(JScrollPane(self.results_table), BorderLayout.CENTER)
        self.clear_button.addActionListener(_ClearButtonListener(self))
        self.copy_rows_button.addActionListener(_CopyRowsButtonListener(self))
        self.hide_4xx_box.addActionListener(_Hide4xxButtonListener(self))

    def _apply_status_filter(self):

        if self.hide_4xx_box.isSelected():

            self.table_sorter.setRowFilter(
                RowFilter.regexFilter(r"^(?!4\d\d$).*", 3)
            )
        else:
            self.table_sorter.setRowFilter(None)

    def _add_config_row(self, panel, gbc, row, label1, field1, label2, field2):
        gbc.gridy = row
        gbc.gridwidth = 1
        gbc.weightx = 0.0
        gbc.gridx = 0
        panel.add(JLabel(label1 + ":"), gbc)
        gbc.gridx = 1
        gbc.weightx = 1.0
        panel.add(field1, gbc)
        gbc.gridx = 2
        gbc.weightx = 0.0
        panel.add(JLabel(label2 + ":"), gbc)
        gbc.gridx = 3
        gbc.weightx = 1.0
        panel.add(field2, gbc)

    def getTabCaption(self):
        return "BAC Replay Auditor"

    def getUiComponent(self):
        return self.main_panel

    def _clear_results(self):
        def clear_on_edt():
            self.table_model.setRowCount(0)
        if SwingUtilities.isEventDispatchThread():
            clear_on_edt()
        else:
            SwingUtilities.invokeLater(clear_on_edt)

    def _set_capture_status(self, message):

        def update_on_edt():
            self.capture_status_label.setText("Status: " + str(message))
        if SwingUtilities.isEventDispatchThread():
            update_on_edt()
        else:
            SwingUtilities.invokeLater(update_on_edt)

    def _start_workers(self, worker_count):
        with self._worker_lock:
            self.worker_target_count = max(1, int(worker_count))
            alive = []
            for worker in self.queue_workers:
                try:
                    if worker.isAlive():
                        alive.append(worker)
                except Exception:
                    pass
            self.queue_workers = alive
            while len(self.queue_workers) < self.worker_target_count:
                index = self._worker_seq
                self._worker_seq += 1
                worker = threading.Thread(
                    target=self._worker_loop,
                    name="BAC-Replay-Worker-%d" % index
                )
                worker.setDaemon(True)
                worker.start()
                self.queue_workers.append(worker)

    def _ensure_workers(self):
        alive_count = 0
        for worker in self.queue_workers:
            try:
                if worker.isAlive():
                    alive_count += 1
            except Exception:
                pass
        now = time.time()
        stalled_count = 0
        with self._active_worker_lock:
            for started_at in self._active_worker_since.values():
                if now - started_at >= self.stalled_worker_seconds:
                    stalled_count += 1
        if stalled_count and self.worker_target_count < self.max_worker_count:
            self.worker_target_count = min(
                self.max_worker_count,
                self.worker_target_count + stalled_count
            )
            self._log_once(
                "worker-stall-expansion",
                "Replay calls appear blocked; the worker pool is being expanded to keep processing queued requests. "
                "If this repeats, check Burp's HTTP timeout and target responsiveness."
            )
        if alive_count < self.worker_target_count:
            self._start_workers(self.worker_target_count)

    def _worker_loop(self):
        while True:
            item = None
            try:
                item = self.work_queue.get()
            except Exception as exc:
                self._log_once("queue-get-error", "Replay worker recovered from queue error: %s" % str(exc))
                continue
            record = None
            key = None
            try:
                if item is None:
                    return
                key, record, http_service, replay_request = item
                worker_name = threading.current_thread().getName()
                with self._active_worker_lock:
                    self._active_worker_since[worker_name] = time.time()
                try:
                    response_info = self.callbacks.makeHttpRequest(http_service, replay_request)
                finally:
                    with self._active_worker_lock:
                        self._active_worker_since.pop(worker_name, None)
                response_bytes = None
                if response_info is not None:
                    response_bytes = response_info.getResponse()
                if response_bytes is None:
                    low_status = "No response"
                    low_length = "-"
                else:
                    low_response_info = self.helpers.analyzeResponse(response_bytes)
                    low_status = str(low_response_info.getStatusCode())
                    low_length = str(max(0, len(response_bytes) - int(low_response_info.getBodyOffset())))
                with record.lock:
                    record.low_status = low_status
                    record.low_length = low_length
                self._maybe_finish_record(key, record)
            except Exception as exc:
                try:
                    self.callbacks.printError("Replay failed: %s" % str(exc))
                except Exception:
                    pass
                if record is not None:
                    with record.lock:
                        record.low_status = "Error"
                        record.low_length = "-"
                        record.forced_analysis = "Replay error; see Extender output"
                    self._maybe_finish_record(key, record)
            finally:
                try:
                    self.work_queue.task_done()
                except Exception:
                    pass

    def processProxyMessage(self, messageIsRequest, message):
        try:
            message_info = message.getMessageInfo()
            if messageIsRequest:
                self._handle_proxy_request(message, message_info)
            else:
                self._handle_proxy_response(message, message_info)
        except Exception as exc:

            self.callbacks.printError("Proxy listener error: %s" % str(exc))

    def _handle_proxy_request(self, intercepted_message, message_info):
        request = message_info.getRequest()
        if request is None:
            return
        http_service = message_info.getHttpService()
        request_info = self.helpers.analyzeRequest(http_service, request)
        method = str(request_info.getMethod()).upper()
        if method == "OPTIONS":
            self._log_once(
                "options-ignored",
                "OPTIONS preflight requests are ignored and will not be cached, replayed, or displayed."
            )
            return
        url_obj = request_info.getUrl()
        url_text = str(url_obj.toString())
        endpoint = self._endpoint_from_url(url_obj)
        request_headers = request_info.getHeaders()

        if self._has_header(request_headers, MARKER_HEADER):
            return

        target_host = self._normalize_host(self.target_host_field.getText())
        request_host = self._normalize_host(http_service.getHost())
        if not target_host or request_host != target_host:
            return

        color = self._header_value(request_headers, COLOR_HEADER)
        if color is None:
            self._log_once("missing-color-header",
                           "Target-host traffic was seen, but X-PwnFox-Color was absent. "
                           "Check that PwnFox adds the header before this listener sees the request.")
            return
        color = color.strip().lower()
        low_color = self.low_color_field.getText().strip().lower()
        admin_color = self.admin_color_field.getText().strip().lower()
        self._log_once("color-seen:" + color,
                       "Observed target request with PwnFox color '%s'." % color)
        self._set_capture_status("Observed PwnFox color '%s' on target traffic." % color)

        if not self._is_in_scope(url_obj):
            self._log_once("out-of-scope:" + request_host,
                           "Target host matched, but the URL is not in Burp Target Scope; "
                           "the extension will not cache cookies or replay requests until it is in scope.")
            return

        if color == low_color and low_color:
            cache_key = self._cookie_key(target_host, low_color)
            cookie = self._header_value(request_headers, "Cookie")
            if cookie:
                previous_cookie = self.low_cookie_by_host.put(cache_key, cookie.strip())
                if previous_cookie is None:
                    self.callbacks.printOutput(
                        "Captured initial low-priv Cookie for %s (PwnFox color=%s); value redacted." %
                        (target_host, low_color))
                elif str(previous_cookie) != cookie.strip():
                    self.callbacks.printOutput(
                        "Updated cached low-priv Cookie for %s (PwnFox color=%s); value redacted." %
                        (target_host, low_color))
            else:
                self._log_once("no-cookie:" + low_color,
                               "A low-priv request with color '%s' was seen, but it had no Cookie header." % low_color)

            replace_names = self._configured_replace_headers()
            fresh_values = {}
            for normalized_name in replace_names.keys():
                value = self._header_value(request_headers, normalized_name)
                if value is not None:
                    fresh_values[normalized_name] = value
            changed_header_names = []
            with self.header_cache_lock:
                previous_values = self.low_headers_by_host.get(cache_key)
                merged_values = dict(previous_values) if previous_values is not None else {}
                for normalized_name, value in fresh_values.items():
                    if merged_values.get(normalized_name) != value:
                        changed_header_names.append(normalized_name)
                    merged_values[normalized_name] = value
                self.low_headers_by_host.put(cache_key, merged_values)

            replace_params = self._configured_replace_parameters()
            fresh_params = {}
            for parameter in request_info.getParameters():
                try:
                    param_name = str(parameter.getName())
                    normalized_name = param_name.lower()
                    param_type = int(parameter.getType())
                    if normalized_name not in replace_params or param_type not in (0, 1, 6):
                        continue
                    param_value = str(parameter.getValue())
                    fresh_params[self._parameter_type_key(param_type, normalized_name)] = param_value
                    fresh_params[self._parameter_name_key(normalized_name)] = param_value
                except Exception:
                    continue

            changed_param_names = []
            with self.header_cache_lock:
                previous_params = self.low_params_by_host.get(cache_key)
                merged_params = dict(previous_params) if previous_params is not None else {}
                for normalized_key, value in fresh_params.items():
                    if merged_params.get(normalized_key) != value:
                        changed_param_names.append(normalized_key.split("|", 1)[-1])
                    merged_params[normalized_key] = value
                self.low_params_by_host.put(cache_key, merged_params)

            cookie_ready = bool(self.low_cookie_by_host.get(cache_key))
            cached_names = sorted(merged_values.keys())
            cached_params = sorted(set(
                item.split("|", 1)[1] for item in merged_params.keys() if item.startswith("name|")
            ))
            self._set_cache_status(
                "Low-priv auth cache: Cookie=%s; headers=%s; parameters=%s" % (
                    "READY" if cookie_ready else "MISSING",
                    ", ".join(cached_names) if cached_names else "none",
                    ", ".join(cached_params) if cached_params else "none"
                )
            )
            if changed_header_names:
                self.callbacks.printOutput(
                    "Captured/updated low-priv header value(s) for %s: %s; values redacted." %
                    (target_host, ", ".join(sorted(changed_header_names))))
            if changed_param_names:
                self.callbacks.printOutput(
                    "Captured/updated low-priv parameter value(s) for %s: %s; values redacted." %
                    (target_host, ", ".join(sorted(set(changed_param_names))))
                )
            if not cookie_ready and not merged_values and not merged_params:
                self._log_once(
                    "low-session-no-auth-material:" + target_host,
                    "Low-priv requests were observed, but no Cookie, configured header, or configured parameter value has been cached yet."
                )
            return

        if not admin_color or admin_color == low_color or color != admin_color:
            return
        if not self.enable_box.isSelected():
            self._log_once("admin-seen-replay-disabled",
                           "Admin-color request was observed, but replay is OFF. "
                           "Enable 'Enable replay (GET/HEAD)' to create result rows.")
            return
        if self._is_excluded(url_text):
            self._log_once("admin-path-excluded",
                           "At least one admin request was skipped by Exclude Paths. Check the field if the expected endpoint is absent.")
            return

        method = str(request_info.getMethod()).upper()
        self._expire_pending_records()
        self._ensure_workers()
        key = str(intercepted_message.getMessageReference())
        if self.pending_by_ref.size() >= self.max_pending:
            self.callbacks.printOutput("BAC replay skipped: pending-result limit reached.")
            return

        cache_key = self._cookie_key(target_host, low_color)
        low_cookie = self.low_cookie_by_host.get(cache_key)
        record = PendingRecord(method, endpoint)
        self.pending_by_ref.put(key, record)

        if method not in ("GET", "HEAD"):
            if method in ("POST", "PUT", "PATCH", "DELETE") and self.allow_write_box.isSelected():
                pass
            else:
                with record.lock:
                    record.low_status = "Not replayed"
                    if method in ("POST", "PUT", "PATCH", "DELETE"):
                        record.forced_analysis = (
                            "Skipped: enable the state-changing-method checkbox to replay %s" % method
                        )
                    else:
                        record.forced_analysis = "Skipped: unsupported HTTP method (%s)" % method
                self._maybe_finish_record(key, record)
                return

        try:
            cached_low_headers = self.low_headers_by_host.get(cache_key)
            if cached_low_headers is None:
                cached_low_headers = {}
            cached_low_params = self.low_params_by_host.get(cache_key)
            if cached_low_params is None:
                cached_low_params = {}
            replay_request = self._build_low_priv_request(
                http_service, request, request_info, low_cookie, low_color,
                cached_low_headers, cached_low_params
            )
            self.work_queue.put_nowait((key, record, http_service, replay_request))
        except Queue.Full:
            with record.lock:
                record.low_status = "Not replayed"
                record.forced_analysis = "Skipped: replay queue is full"
            self.callbacks.printOutput("BAC replay skipped: replay queue is full.")
            self._maybe_finish_record(key, record)
        except Exception as exc:
            with record.lock:
                record.low_status = "Error"
                record.low_length = "-"
                record.forced_analysis = "Could not build replay request"
            self.callbacks.printError("Could not build replay request: %s" % str(exc))
            self._maybe_finish_record(key, record)

        self._maybe_finish_record(key, record)

    def _expire_pending_records(self):
        now = time.time()
        try:
            keys = list(self.pending_by_ref.keySet())
        except Exception:
            return
        for key in keys:
            record = self.pending_by_ref.get(key)
            if record is None:
                continue
            row = None
            with record.lock:
                if record.complete or now - record.created_at < self.pending_ttl_seconds:
                    continue
                if record.admin_status is None:
                    record.admin_status = "Timed out"
                if record.low_status is None:
                    record.low_status = "Timed out"
                if record.admin_length is None:
                    record.admin_length = "-"
                if record.low_length is None:
                    record.low_length = "-"
                record.forced_analysis = "Timed out: stale pending result cleared"
                record.complete = True
                row = [record.method, record.endpoint, record.admin_status,
                       record.low_status, record.admin_length, record.low_length,
                       record.forced_analysis]
            self.pending_by_ref.remove(key)
            if row is not None:
                def add_expired_row(values=row):
                    self.table_model.addRow(values)
                SwingUtilities.invokeLater(add_expired_row)

    def _handle_proxy_response(self, intercepted_message, message_info):
        key = str(intercepted_message.getMessageReference())
        record = self.pending_by_ref.get(key)
        if record is None:
            return
        response = message_info.getResponse()
        if response is None:
            admin_status = "No response"
            admin_length = "-"
        else:
            try:
                response_details = self.helpers.analyzeResponse(response)
                admin_status = str(response_details.getStatusCode())
                admin_length = str(max(0, len(response) - int(response_details.getBodyOffset())))
            except Exception:
                admin_status = "Unknown"
                admin_length = "-"
        with record.lock:
            record.admin_status = admin_status
            record.admin_length = admin_length
        self._maybe_finish_record(key, record)

    def _build_low_priv_request(self, http_service, original_request, request_info,
                                low_cookie, low_color, cached_low_headers, cached_low_params):
        original_headers = request_info.getHeaders()
        replace_names = self._configured_replace_headers()
        keep_names = self._parse_header_names(self.keep_admin_headers_field.getText())
        replace_params = self._configured_replace_parameters()
        sensitive_headers = set([
            "authorization", "proxy-authorization", "x-api-key",
            "x-auth-token", "x-access-token", "x-csrf-token"
        ])
        blocked_headers = set([
            "cookie", "content-length", "transfer-encoding", "connection",
            "proxy-connection", COLOR_HEADER.lower(), MARKER_HEADER.lower()
        ])
        headers = ArrayList()
        admin_header_names = set()

        for header in original_headers:
            header_text = str(header)
            header_name = header_text.split(":", 1)[0].strip().lower()
            if not header_name:
                continue
            admin_header_names.add(header_name)
            if header_name in blocked_headers or header_name in replace_names:
                continue
            if header_name in sensitive_headers and header_name not in keep_names:
                continue
            headers.add(header)

        missing_low_headers = []
        for normalized_name, display_name in replace_names.items():
            if normalized_name not in admin_header_names:
                continue
            low_value = cached_low_headers.get(normalized_name)
            if low_value is not None and str(low_value) != "":
                headers.add("%s: %s" % (display_name, str(low_value)))
            else:
                missing_low_headers.append(display_name)

        if missing_low_headers:
            self._log_once(
                "missing-low-header-values:" + ",".join(sorted([v.lower() for v in missing_low_headers])),
                "No low-priv value was captured for configured header(s): %s. "
                "The admin values were removed from the replay instead of being reused." %
                ", ".join(missing_low_headers)
            )

        if low_cookie:
            headers.add("Cookie: %s" % str(low_cookie))
        headers.add("%s: %s" % (COLOR_HEADER, low_color))
        headers.add("%s: 1" % MARKER_HEADER)

        body_offset = int(request_info.getBodyOffset())
        body = original_request[body_offset:]
        json_parameters = []
        for parameter in request_info.getParameters():
            try:
                if int(parameter.getType()) == 6 and str(parameter.getName()).lower() in replace_params:
                    json_parameters.append(parameter)
            except Exception:
                continue
        if json_parameters:
            try:
                body_text = String(body, "UTF-8").toString()
                json_value = json.loads(body_text)
                missing_json_params = []
                json_value = self._rewrite_json_value(
                    json_value, replace_params, cached_low_params, missing_json_params
                )
                rebuilt_json = json.dumps(json_value, separators=(",", ":"), ensure_ascii=False)
                body = String(rebuilt_json.encode("UTF-8"), "UTF-8").getBytes("UTF-8")
                if missing_json_params:
                    self._log_once(
                        "missing-low-json-values:" + ",".join(sorted(set([n.lower() for n in missing_json_params]))),
                        "No low-priv value was cached for configured JSON parameter(s): %s. "
                        "Those admin JSON properties were removed from the replay." %
                        ", ".join(sorted(set(missing_json_params)))
                    )
            except Exception as exc:
                raise Exception("Could not safely rewrite JSON request body: %s" % str(exc))
        replay_request = self.helpers.buildHttpMessage(headers, body)

        missing_params = []
        param_specs = {}
        for parameter in request_info.getParameters():
            try:
                param_name = str(parameter.getName())
                normalized_name = param_name.lower()
                param_type = int(parameter.getType())
                if normalized_name in replace_params and param_type in (0, 1):
                    param_specs[(param_type, normalized_name)] = param_name
            except Exception:
                continue

        for param_identity, param_name in param_specs.items():
            param_type, normalized_name = param_identity
            try:
                low_value = self._get_cached_parameter_value(
                    cached_low_params, param_type, normalized_name
                )
                current_info = self.helpers.analyzeRequest(http_service, replay_request)
                matches = [p for p in current_info.getParameters()
                           if int(p.getType()) == param_type and str(p.getName()).lower() == normalized_name]
                if low_value is None:
                    while matches:
                        replay_request = self.helpers.removeParameter(replay_request, matches[0])
                        current_info = self.helpers.analyzeRequest(http_service, replay_request)
                        matches = [p for p in current_info.getParameters()
                                   if int(p.getType()) == param_type and str(p.getName()).lower() == normalized_name]
                    missing_params.append(param_name)
                elif matches:
                    replacement = self.helpers.buildParameter(param_name, str(low_value), param_type)
                    replay_request = self.helpers.updateParameter(replay_request, replacement)
            except Exception:
                self._log_once(
                    "parameter-rewrite-error",
                    "A configured query/form parameter could not be rewritten. Verify its name and request format."
                )

        if missing_params:
            self._log_once(
                "missing-low-param-values:" + ",".join(sorted(set([n.lower() for n in missing_params]))),
                "No low-priv value was cached for configured parameter(s): %s. "
                "Those admin parameter(s) were removed from the replay." %
                ", ".join(sorted(set(missing_params)))
            )
        return replay_request

    def _maybe_finish_record(self, key, record):
        row = None
        with record.lock:
            if record.complete:
                return
            if record.admin_status is None or record.low_status is None:
                return
            record.complete = True
            admin_status = record.admin_status
            low_status = record.low_status
            admin_length = record.admin_length if record.admin_length is not None else "-"
            low_length = record.low_length if record.low_length is not None else "-"
            if record.forced_analysis:
                analysis = record.forced_analysis
            elif low_status == "200":
                analysis = "POTENTIAL BAC (200 OK)!"
            elif low_status in ("Error", "No response"):
                analysis = "Inconclusive: low-privilege replay failed"
            elif low_status == "Not replayed":
                analysis = "Not tested"
            else:
                analysis = "Secure (low-priv status %s)" % low_status
            row = [record.method, record.endpoint, admin_status, low_status,
                   admin_length, low_length, analysis]

        self.pending_by_ref.remove(key)
        if row is not None:
            def add_row_on_edt(values=row):
                self.table_model.addRow(values)
            SwingUtilities.invokeLater(add_row_on_edt)

    def _copy_selected_cells_to_clipboard(self):
        rows = list(self.results_table.getSelectedRows())
        cols = list(self.results_table.getSelectedColumns())
        if not rows or not cols:
            self.callbacks.printOutput("BAC: select one or more table cells before copying.")
            return
        lines = []
        for row in rows:
            model_row = self.results_table.convertRowIndexToModel(row)
            values = []
            for col in cols:
                if self.results_table.isCellSelected(row, col):
                    model_col = self.results_table.convertColumnIndexToModel(col)
                    value = self.table_model.getValueAt(model_row, model_col)
                    values.append("" if value is None else str(value))
                else:
                    values.append("")
            lines.append("\t".join(values))
        self._copy_text_to_clipboard("\n".join(lines))

    def _copy_selected_rows_to_clipboard(self):
        rows = list(self.results_table.getSelectedRows())
        if not rows:
            self.callbacks.printOutput("BAC: select one or more table rows before copying rows.")
            return
        headers = [str(self.table_model.getColumnName(col))
                   for col in range(self.table_model.getColumnCount())]
        lines = ["\t".join(headers)]
        for row in rows:
            model_row = self.results_table.convertRowIndexToModel(row)
            values = []
            for col in range(self.table_model.getColumnCount()):
                model_col = self.results_table.convertColumnIndexToModel(col)
                value = self.table_model.getValueAt(model_row, model_col)
                values.append("" if value is None else str(value))
            lines.append("\t".join(values))
        self._copy_text_to_clipboard("\n".join(lines))

    def _copy_text_to_clipboard(self, text):
        try:
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(text), None)
            self.callbacks.printOutput("BAC: copied selection to clipboard.")
        except Exception as exc:
            self.callbacks.printError("BAC: could not copy to clipboard: %s" % str(exc))

    def _log_once(self, key, message):
        should_log = False
        with self._diagnostic_lock:
            if key not in self._diagnostics_emitted:
                self._diagnostics_emitted.add(key)
                should_log = True
        if should_log:
            self.callbacks.printOutput("[BAC diagnostics] %s" % message)

    def _set_cache_status(self, text):
        def update_label():
            if hasattr(self, "cache_status_label"):
                self.cache_status_label.setText(text)
        if SwingUtilities.isEventDispatchThread():
            update_label()
        else:
            SwingUtilities.invokeLater(update_label)

    def _endpoint_from_url(self, url_obj):
        try:
            path = str(url_obj.getPath() or "/")
            query = url_obj.getQuery()
            if query:
                return path + "?" + str(query)
            return path
        except Exception:
            return str(url_obj.toString())

    def _configured_replace_parameters(self):
        result = {}
        for part in str(self.replace_parameters_field.getText()).split(","):
            name = part.strip()
            if not name or "\r" in name or "\n" in name:
                continue
            result[name.lower()] = name
        return result

    def _parameter_type_key(self, param_type, normalized_name):
        type_names = {0: "url", 1: "body", 6: "json"}
        return "%s|%s" % (type_names.get(int(param_type), str(param_type)), normalized_name)

    def _parameter_name_key(self, normalized_name):
        return "name|%s" % normalized_name

    def _get_cached_parameter_value(self, cached_params, param_type, normalized_name):
        type_key = self._parameter_type_key(param_type, normalized_name)
        value = cached_params.get(type_key)
        if value is not None:
            return value
        return cached_params.get(self._parameter_name_key(normalized_name))

    def _rewrite_json_value(self, value, replace_params, cached_low_params, missing_names):
        if isinstance(value, dict):
            for key in list(value.keys()):
                normalized_name = str(key).lower()
                if normalized_name in replace_params:
                    low_value = self._get_cached_parameter_value(
                        cached_low_params, 6, normalized_name
                    )
                    if low_value is None:
                        del value[key]
                        missing_names.append(str(key))
                    else:
                        value[key] = str(low_value)
                else:
                    value[key] = self._rewrite_json_value(
                        value[key], replace_params, cached_low_params, missing_names
                    )
            return value
        if isinstance(value, list):
            return [self._rewrite_json_value(item, replace_params, cached_low_params, missing_names)
                    for item in value]
        return value

    def _cookie_key(self, host, color):
        return "%s|%s" % (host, color.lower())

    def _normalize_host(self, raw_host):
        if raw_host is None:
            return ""
        host = str(raw_host).strip().lower()
        if not host:
            return ""
        if "://" in host:
            try:
                from java.net import URL
                return str(URL(host).getHost()).lower()
            except Exception:
                pass
        host = host.split("/", 1)[0]
        if host.startswith("[") and "]" in host:
            return host[1:host.index("]")]
        if ":" in host:
            host = host.split(":", 1)[0]
        return host.strip().rstrip(".")

    def _is_in_scope(self, url_obj):
        try:
            return bool(self.callbacks.isInScope(url_obj))
        except Exception:
            return False

    def _header_value(self, headers, name):
        wanted = name.lower()
        for header in headers:
            text = str(header)
            if ":" not in text:
                continue
            header_name, value = text.split(":", 1)
            if header_name.strip().lower() == wanted:
                return value.strip()
        return None

    def _has_header(self, headers, name):
        return self._header_value(headers, name) is not None

    def _parse_header_names(self, raw):
        result = {}
        blocked = set([
            "cookie", "host", "content-length", "transfer-encoding", "connection",
            "proxy-connection", COLOR_HEADER.lower(), MARKER_HEADER.lower()
        ])
        for part in str(raw).split(","):
            name = part.strip()
            if not name or ":" in name or "\r" in name or "\n" in name:
                continue
            normalized = name.lower()
            if normalized in blocked:
                self._log_once(
                    "blocked-header-config:" + normalized,
                    "Header '%s' is controlled by the extension/HTTP builder and was ignored in the header lists." % name
                )
                continue
            result[normalized] = name
        return result

    def _configured_replace_headers(self):
        return self._parse_header_names(self.replace_headers_field.getText())

    def _is_excluded(self, url_text):
        raw = self.exclude_field.getText()
        tokens = [part.strip().lower() for part in str(raw).split(",") if part.strip()]
        url_lower = url_text.lower()
        for token in tokens:
            if token in url_lower:
                return True
        return False

class _BacRowRenderer(DefaultTableCellRenderer):

    def __init__(self, extender):
        DefaultTableCellRenderer.__init__(self)
        self.extender = extender

    def getTableCellRendererComponent(self, table, value, is_selected, has_focus, row, column):
        component = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, is_selected, has_focus, row, column
        )
        try:
            model_row = table.convertRowIndexToModel(row)
            low_status = str(self.extender.table_model.getValueAt(model_row, 3))
            if low_status == "200":
                component.setBackground(Color(180, 0, 0))
                component.setForeground(Color.WHITE)
            else:
                component.setBackground(
                    table.getSelectionBackground() if is_selected else table.getBackground()
                )
                component.setForeground(
                    table.getSelectionForeground() if is_selected else table.getForeground()
                )
        except Exception:
            pass
        return component

class _Hide4xxButtonListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, event):
        self.extender._apply_status_filter()

class _CopyCellsAction(AbstractAction):
    def __init__(self, extender):
        AbstractAction.__init__(self, "Copy selected cells")
        self.extender = extender

    def actionPerformed(self, event):
        self.extender._copy_selected_cells_to_clipboard()

class _CopyCellsButtonListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, event):
        self.extender._copy_selected_cells_to_clipboard()

class _CopyRowsButtonListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, event):
        self.extender._copy_selected_rows_to_clipboard()

class _SelectCellOnPopupListener(MouseAdapter):
    def __init__(self, extender):
        self.extender = extender

    def _select_clicked_cell(self, event):
        if not event.isPopupTrigger():
            return
        table = self.extender.results_table
        row = table.rowAtPoint(event.getPoint())
        col = table.columnAtPoint(event.getPoint())
        if row >= 0 and col >= 0 and not table.isCellSelected(row, col):
            table.changeSelection(row, col, False, False)

    def mousePressed(self, event):
        self._select_clicked_cell(event)

    def mouseReleased(self, event):
        self._select_clicked_cell(event)

class _ClearButtonListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, event):
        self.extender._clear_results()

class _BuildUiRunnable(Runnable):
    def __init__(self, extender):
        self.extender = extender

    def run(self):
        self.extender._build_ui()