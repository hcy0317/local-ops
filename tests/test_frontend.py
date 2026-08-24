from html.parser import HTMLParser
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


def relative_luminance(color):
    channels = [int(color[index:index + 2], 16) / 255
                for index in (1, 3, 5)]
    channels = [
        value / 12.92 if value <= 0.04045
        else ((value + 0.055) / 1.055) ** 2.4
        for value in channels
    ]
    return (
        0.2126 * channels[0]
        + 0.7152 * channels[1]
        + 0.0722 * channels[2]
    )


def contrast_ratio(foreground, background):
    lighter, darker = sorted(
        (relative_luminance(foreground), relative_luminance(background)),
        reverse=True,
    )
    return (lighter + 0.05) / (darker + 0.05)


def theme_block(source, selector):
    match = re.search(
        re.escape(selector) + r"\s*\{(?P<body>[^}]+)\}",
        source,
    )
    if not match:
        raise AssertionError(f"Missing theme block: {selector}")
    return match.group("body")


def theme_token_block(source, color_scheme):
    for match in re.finditer(
        r"(?P<selector>[^{}]+)\{(?P<body>[^{}]+)\}",
        source,
    ):
        body = match.group("body")
        if (
            re.search(rf"color-scheme:\s*{re.escape(color_scheme)}\s*;", body)
            and "--ink-4:" in body
        ):
            return body
    raise AssertionError(f"Missing {color_scheme} theme token block")


def css_variable(block, name):
    match = re.search(
        rf"--{re.escape(name)}:\s*(#[0-9a-fA-F]{{6}})",
        block,
    )
    if not match:
        raise AssertionError(f"Missing CSS color variable: --{name}")
    return match.group(1)


class FrontendStructureParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.tables = []
        self.buttons_inside_labels = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        active_table = next(
            (item["table"] for item in reversed(self.stack)
             if item["table"] is not None),
            None,
        )
        if attributes.get("role") == "table":
            active_table = {
                "label": attributes.get("aria-label"),
                "rows": 0,
                "headers": 0,
            }
            self.tables.append(active_table)
        if active_table is not None:
            if attributes.get("role") == "row":
                active_table["rows"] += 1
            if attributes.get("role") == "columnheader":
                active_table["headers"] += 1
        if tag == "button" and any(item["tag"] == "label" for item in self.stack):
            self.buttons_inside_labels.append(attributes.get("id", "anonymous"))
        self.stack.append({
            "tag": tag,
            "table": active_table if attributes.get("role") == "table" else None,
        })

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index]["tag"] == tag:
                del self.stack[index:]
                return


class FrontendAccessibilityContractTests(unittest.TestCase):
    def test_monitoring_tables_have_named_aria_structure(self):
        parser = FrontendStructureParser()
        parser.feed((ROOT / "static/index.html").read_text(encoding="utf-8"))

        self.assertEqual(
            [table["label"] for table in parser.tables],
            ["我的服务", "应用后台", "已隐藏服务", "关注的进程"],
        )
        self.assertEqual(
            [table["headers"] for table in parser.tables],
            [9, 9, 9, 5],
        )
        self.assertTrue(all(table["rows"] >= 1 for table in parser.tables))

    def test_form_labels_do_not_contain_buttons(self):
        parser = FrontendStructureParser()
        parser.feed((ROOT / "static/index.html").read_text(encoding="utf-8"))
        self.assertEqual(parser.buttons_inside_labels, [])

    def test_accessibility_and_narrow_screen_css_guards_exist(self):
        css = (ROOT / "static/base.css").read_text(encoding="utf-8")
        self.assertIn("@media (forced-colors: active)", css)
        self.assertIn(".app-grid { grid-template-columns: minmax(0, 1fr); }", css)
        self.assertIn(".tbl .tr.th > * { display: block !important; }", css)
        self.assertNotIn(".tbl .tr.th { display: none; }", css)

    def test_tactical_editorial_console_uses_rigid_operational_grid(self):
        html = (ROOT / "static/index.html").read_text(encoding="utf-8")
        ops = (ROOT / "static/themes/ops.css").read_text(encoding="utf-8")
        base = (ROOT / "static/base.css").read_text(encoding="utf-8")

        self.assertIn('data-ui="tactical-editorial"', html)
        self.assertIn("--panel-radius: 2px;", ops)

        headline = theme_block(ops, ".view-head h2")
        self.assertIn("font-size: 64px", headline)

        overview = theme_block(ops, ".ov-row")
        self.assertIn("gap: 1px", overview)
        self.assertIn("border: 1px solid var(--line-2)", overview)

        grid = theme_block(ops, ".app-grid")
        self.assertIn("gap: 1px", grid)
        self.assertIn("border: 1px solid var(--line-2)", grid)

        empty_grid_action = theme_block(
            ops,
            ".app-grid > .add-card:only-child",
        )
        self.assertIn("grid-column: 1 / -1", empty_grid_action)
        self.assertIn("min-height: 112px", empty_grid_action)

        card = theme_block(ops, ".app-card")
        self.assertIn("border-radius: var(--panel-radius)", card)
        self.assertNotIn("border-top", card)
        self.assertNotIn("box-shadow", theme_block(ops, ".app-card:hover"))
        self.assertNotIn(".app-card.running { border-top-color", ops)
        self.assertNotIn(".app-card.has-error { border-top-color", ops)
        self.assertNotIn(".view-head::before", ops)

        texture = theme_block(ops, "body::before")
        self.assertIn("position: fixed", texture)
        self.assertIn("pointer-events: none", texture)

        telemetry = theme_block(base, ".side-stack")
        self.assertIn("gap: 1px", telemetry)
        self.assertIn("border: 1px solid var(--line-2)", telemetry)

    def test_tactical_editorial_motion_omits_sweeping_light_effects(self):
        ops = (ROOT / "static/themes/ops.css").read_text(encoding="utf-8")
        core = (ROOT / "static/js/core.js").read_text(encoding="utf-8")

        self.assertNotIn("@keyframes telemetry-sweep", ops)
        self.assertIn("@keyframes status-pulse", ops)
        self.assertIn("@keyframes signal-enter", ops)
        self.assertIn("@keyframes signal-exit", ops)
        self.assertIn("@keyframes view-out", ops)
        self.assertNotIn("animation: telemetry-sweep", ops)
        self.assertNotIn(".topbar::after", ops)
        self.assertNotIn(".ov-row::after", ops)
        self.assertIn("animation: status-pulse 2.4s", ops)
        self.assertIn(
            "node.classList.remove('flash');\n"
            "  void node.offsetWidth;\n"
            "  node.classList.add('flash');",
            core,
        )
        self.assertIn("node.classList.add('anim-out')", core)
        self.assertIn("node.remove()", core)

        app = (ROOT / "static/app.js").read_text(encoding="utf-8")
        self.assertIn("classList.add('is-leaving')", app)

        card_marker = theme_block(ops, ".app-card::before")
        self.assertIn("transform: scaleY(0)", card_marker)
        self.assertIn(
            "transform: scaleY(1)",
            theme_block(ops, ".app-card:hover::before"),
        )

        self.assertRegex(
            ops,
            r"(?s)@media \(prefers-reduced-motion: reduce\)\s*\{.*?"
            r"\.status-dot\.running::after\s*"
            r"\{[^}]*display:\s*none;",
        )

    def test_focus_indicators_avoid_hard_double_rings(self):
        base = (ROOT / "static/base.css").read_text(encoding="utf-8")

        self.assertIn(
            ".appearance-details summary:focus-visible .appearance-disclosure",
            base,
        )
        self.assertIn("text-decoration-thickness: 2px", base)
        self.assertNotIn(
            "box-shadow: var(--focus-ring) !important;\n}"
            "\n\n.appearance-details[open]",
            base,
        )

    def test_ops_hero_english_companion_uses_single_light_layer(self):
        ops = (ROOT / "static/themes/ops.css").read_text(encoding="utf-8")
        english = theme_block(ops, ".view-head h2::after")

        self.assertIn("content: 'LAUNCHPAD'", english)
        self.assertIn("display: inline-block", english)
        self.assertIn("font-family: var(--font-mono)", english)
        self.assertNotIn("color: transparent", english)
        self.assertNotIn("-webkit-text-stroke: 1", english)
        self.assertRegex(
            ops,
            r"(?s)@media \(max-width: 900px\)\s*\{.*?"
            r"\.view-head h2::after\s*\{[^}]*display:\s*block;",
        )

    def test_small_text_color_pairs_meet_wcag_aa(self):
        ops = (ROOT / "static/themes/ops.css").read_text(encoding="utf-8")
        ops_light = theme_token_block(ops, "light")
        ops_dark = theme_token_block(ops, "dark")

        pairs = [
            (css_variable(ops_light, "ink-4"),
             css_variable(ops_light, "room")),
            (css_variable(ops_dark, "ink-4"),
             css_variable(ops_dark, "card")),
            (css_variable(ops_light, "accent"),
             css_variable(ops_light, "card")),
            (css_variable(ops_dark, "accent"),
             css_variable(ops_dark, "card")),
            (css_variable(ops_light, "green"),
             css_variable(ops_light, "card")),
            (css_variable(ops_light, "red"),
             css_variable(ops_light, "card")),
            (css_variable(ops_dark, "red"),
             css_variable(ops_dark, "card")),
        ]
        for foreground, background in pairs:
            with self.subTest(foreground=foreground, background=background):
                self.assertGreaterEqual(
                    contrast_ratio(foreground, background),
                    4.5,
                )

    def test_light_theme_uses_high_contrast_cool_neutrals(self):
        ops = (ROOT / "static/themes/ops.css").read_text(encoding="utf-8")
        light = theme_token_block(ops, "light")
        room = css_variable(light, "room")
        card = css_variable(light, "card")

        self.assertGreaterEqual(int(room[5:7], 16), int(room[1:3], 16))
        self.assertGreaterEqual(int(card[5:7], 16), int(card[1:3], 16))
        for name, minimum in (
            ("ink", 12.0),
            ("ink-2", 8.0),
            ("ink-3", 5.5),
            ("ink-4", 4.5),
            ("accent", 5.0),
            ("green", 4.5),
            ("red", 4.5),
            ("amber", 4.5),
        ):
            with self.subTest(token=name):
                self.assertGreaterEqual(
                    contrast_ratio(css_variable(light, name), card),
                    minimum,
                )

    def test_linked_service_action_edits_instead_of_duplicating(self):
        source = (ROOT / "static/js/services.js").read_text(encoding="utf-8")
        self.assertIn("if (s.appId)", source)
        self.assertIn("if (linked) openAppModal(linked);", source)
        self.assertIn("linked ? 'pencil' : 'plus'", source)
        self.assertIn("svc.appId ? '编辑启动台应用' : hasCapability('attach_external')", source)
        self.assertNotIn("configuredPortClaims", source)

    def test_adding_a_running_service_creates_and_attaches_in_one_flow(self):
        services = (ROOT / "static/js/services.js").read_text(encoding="utf-8")
        overlays = (ROOT / "static/js/overlays.js").read_text(encoding="utf-8")

        self.assertIn("if (hasCapability('attach_external'))", services)
        self.assertIn("draft.attachPid = s.pid", services)
        self.assertIn("let pendingAttach = null", overlays)
        self.assertIn("保存并认领", overlays)
        self.assertIn("body.attachPid = attachRequest.pid", overlays)
        self.assertIn("app.attached", overlays)
        self.assertIn("willAttach && detectingProject", overlays)
        self.assertIn("已加入启动台并认领正在运行的进程", overlays)

    def test_task_outcomes_and_health_have_distinct_ui_contracts(self):
        core = (ROOT / "static/js/core.js").read_text(encoding="utf-8")
        launchpad = (ROOT / "static/js/launchpad.js").read_text(encoding="utf-8")
        overlays = (ROOT / "static/js/overlays.js").read_text(encoding="utf-8")

        self.assertIn("export function taskExitStatus", core)
        self.assertIn("lastExit.code === 130", core)
        for status in ("succeeded", "canceled", "failed", "stopped"):
            self.assertIn(f"'{status}'", core)
        self.assertIn("taskStatus === 'canceled' ? '已取消' : '已中止'", launchpad)
        self.assertIn("app.health && app.health.blocking", launchpad)
        self.assertIn("r.primary.disabled = blocked", launchpad)
        self.assertIn("配置与运行诊断", launchpad)
        self.assertIn("const isTask = modalKind === 'task'", overlays)
        self.assertIn("const stopVerb = isTask ? '中止任务' : '停止服务'", overlays)

    def test_windows_scheduled_tasks_are_selectable_and_render_native_state(self):
        html = (ROOT / "static/index.html").read_text(encoding="utf-8")
        overlays = (ROOT / "static/js/overlays.js").read_text(encoding="utf-8")
        launchpad = (ROOT / "static/js/launchpad.js").read_text(encoding="utf-8")
        app = (ROOT / "static/app.js").read_text(encoding="utf-8")

        self.assertIn('id="scheduledTaskField"', html)
        self.assertIn('id="fScheduledTaskPath"', html)
        self.assertIn("'/api/windows/scheduled-tasks'", overlays)
        self.assertIn("scheduledTaskPath", overlays)
        self.assertIn("app.runtimeSource === 'windowsTaskScheduler'", launchpad)
        self.assertIn("app.scheduledTask", launchpad)
        self.assertIn("'stop_scheduled_tasks'", launchpad)
        self.assertIn("scheduledTaskControlAvailable", launchpad)
        self.assertIn("'toggle_scheduled_tasks'", launchpad)
        self.assertIn("'/scheduled-enabled'", launchpad)
        self.assertIn("'stop_scheduled_tasks'", app)

    def test_scheduled_task_ready_state_is_distinct_from_running(self):
        launchpad = (ROOT / "static/js/launchpad.js").read_text(encoding="utf-8")
        ops = (ROOT / "static/themes/ops.css").read_text(encoding="utf-8")

        self.assertIn("const scheduledReady = isScheduled", launchpad)
        self.assertIn("classList.toggle('ready', scheduledReady && !dotFailure)", launchpad)
        self.assertIn(
            "classList.toggle('success', taskSucceeded && !isScheduled && !dotFailure)",
            launchpad,
        )

        ready = theme_block(ops, ".status-dot.ready")
        self.assertIn("background: var(--amber)", ready)
        self.assertNotIn(".status-dot.ready::after", ops)
        self.assertIn("animation: status-pulse", theme_block(ops, ".status-dot.running::after"))

    def test_docker_compose_and_container_resources_are_selectable_and_controllable(self):
        html = (ROOT / "static/index.html").read_text(encoding="utf-8")
        overlays = (ROOT / "static/js/overlays.js").read_text(encoding="utf-8")
        launchpad = (ROOT / "static/js/launchpad.js").read_text(encoding="utf-8")

        self.assertIn('id="dockerResourceField"', html)
        self.assertIn('id="fDockerResource"', html)
        self.assertIn("'/api/docker/resources'", overlays)
        self.assertIn("dockerResource", overlays)
        self.assertIn("app.runtimeSource === 'dockerCompose'", launchpad)
        self.assertIn("app.runtimeSource === 'dockerContainer'", launchpad)
        self.assertIn("'control_docker'", launchpad)

    def test_program_favorites_use_session_unlocked_elevation_broker(self):
        html = (ROOT / "static/index.html").read_text(encoding="utf-8")
        overlays = (ROOT / "static/js/overlays.js").read_text(encoding="utf-8")
        launchpad = (ROOT / "static/js/launchpad.js").read_text(encoding="utf-8")
        lifecycle = (ROOT / "static/js/lifecycle.js").read_text(encoding="utf-8")
        app = (ROOT / "static/app.js").read_text(encoding="utf-8")

        self.assertIn('id="programGrid"', html)
        self.assertIn('id="addProgramCard"', html)
        self.assertIn('data-kind="program"', html)
        self.assertIn('id="elevatedField"', html)
        self.assertIn('id="fProgramArgs"', html)
        self.assertIn('id="brokerPasswordMask"', html)
        self.assertIn("'/api/windows/elevation-broker/install'", overlays)
        self.assertIn("'/api/windows/elevation-broker/unlock'", overlays)
        self.assertIn("'BROKER_PACKAGE_REQUIRED'", overlays)
        self.assertIn("packageExecutable", overlays)
        self.assertIn("系统会自动使用已部署的 Windows 伴随包", overlays)
        self.assertRegex(
            overlays,
            r"post\('/api/pick', \{\s*what: modalKind === 'program'"
            r" \? 'exe' : 'script',\s*\}\)",
        )
        self.assertIn("act, toast, state, openLayer", overlays)
        self.assertIn("elevated", overlays)
        self.assertIn("app.runtimeSource === 'windowsElevationBroker'", launchpad)
        self.assertIn("'launch_elevated'", launchpad)
        self.assertIn("app.programStopAvailable", launchpad)
        self.assertIn("expectedProcesses", lifecycle)
        self.assertIn("title: '停止程序'", launchpad)
        self.assertIn("toggleApp(id, button, intent, true)", launchpad)
        self.assertNotIn("launchOnlyObserved", launchpad)
        self.assertIn("app.observedRestricted", launchpad)
        self.assertIn("promptForElevationSession", app)
        self.assertIn("brokerPromptedConsolePid", app)
        self.assertIn("closeBrokerPassword", app)
        self.assertIn("$('#brokerPasswordMask').classList.contains('open')", app)

    def test_program_ui_uses_direct_program_wording(self):
        sources = [
            (ROOT / "static/index.html").read_text(encoding="utf-8"),
            (ROOT / "static/app.js").read_text(encoding="utf-8"),
            (ROOT / "static/js/launchpad.js").read_text(encoding="utf-8"),
            (ROOT / "static/js/overlays.js").read_text(encoding="utf-8"),
        ]

        for source in sources:
            self.assertNotIn("程序收藏", source)
            self.assertNotIn("收藏程序", source)
        self.assertIn("Programs · 程序", sources[0])
        self.assertIn("添加程序", sources[0])

    def test_scheduled_task_log_drawer_can_enable_history(self):
        html = (ROOT / "static/index.html").read_text(encoding="utf-8")
        overlays = (ROOT / "static/js/overlays.js").read_text(encoding="utf-8")

        self.assertIn('id="logSourceStatus"', html)
        self.assertIn('id="logTaskHistoryEnable"', html)
        self.assertIn("j.taskHistory", overlays)
        self.assertIn("'/scheduled-history'", overlays)
        self.assertIn("已启用 Windows 任务历史", overlays)

    def test_watched_process_row_can_remove_its_keywords_without_killing_process(self):
        services = (ROOT / "static/js/services.js").read_text(encoding="utf-8")

        self.assertIn("const bUnwatch = iconBtn('eye-off', '取消关注')", services)
        self.assertIn("Array.isArray(w.keywords)", services)
        self.assertIn("action: 'remove'", services)
        self.assertIn("不会结束进程", services)

    def test_health_notice_does_not_report_connection_loss(self):
        app = (ROOT / "static/app.js").read_text(encoding="utf-8")
        widgets = (ROOT / "static/js/widgets.js").read_text(encoding="utf-8")
        ops = (ROOT / "static/themes/ops.css").read_text(encoding="utf-8")

        self.assertIn("banner.dataset.connection = ok ? 'up' : 'down'", app)
        self.assertIn("banner.dataset.connection === 'down'", widgets)
        self.assertIn("attributeFilter: ['data-connection']", widgets)
        self.assertNotIn("banner.classList.contains('show')", widgets)
        self.assertNotIn(
            "messages.push('配置已从旧版本升级')",
            app,
        )
        self.assertIn("function notifyConfigMigration(data)", app)
        self.assertIn("migrationNotifiedConsolePid", app)
        self.assertIn("notifyConfigMigration(data);", app)
        self.assertEqual(app.count("banner.dataset.connection = 'down'"), 2)
        self.assertIn(".banner.show ~ .shell > .rail", ops)
        self.assertIn(".banner.show ~ .shell > .shell-col { padding-top: 38px; }", ops)

    def test_cwd_changes_discard_only_stale_command_compatibility(self):
        overlays = (ROOT / "static/js/overlays.js").read_text(encoding="utf-8")

        helper = re.search(
            r"function invalidateCommandCompatibility\(\) \{(?P<body>.*?)\n\}",
            overlays,
            re.DOTALL,
        )
        self.assertIsNotNone(helper)
        self.assertIn("selectedCompatibility = null;", helper.group("body"))
        self.assertNotIn("selectedCommandSpec =", helper.group("body"))
        self.assertIn(
            "fCwd.value = r.path;\n        invalidateCommandCompatibility();",
            overlays,
        )
        self.assertIn(
            "fCwd.addEventListener('input', () => {\n"
            "    invalidateCommandCompatibility();",
            overlays,
        )

    def test_log_drawer_layers_above_banner_and_below_toast(self):
        overlays = (ROOT / "static/js/overlays.js").read_text(encoding="utf-8")
        ops = (ROOT / "static/themes/ops.css").read_text(encoding="utf-8")

        self.assertIn("const text = j.text || '暂无日志';", overlays)

        def z_index(selector):
            match = re.search(r"z-index:\s*(\d+)", theme_block(ops, selector))
            self.assertIsNotNone(match, f"Missing z-index for {selector}")
            return int(match.group(1))

        banner = z_index(".banner")
        drawer_mask = z_index(".drawer-mask")
        drawer = z_index(".drawer")
        toast = z_index(".toast")
        self.assertLess(banner, drawer_mask)
        self.assertLess(drawer_mask, drawer)
        self.assertLess(drawer, toast)

    def test_console_controls_follow_platform_capability(self):
        app = (ROOT / "static/app.js").read_text(encoding="utf-8")

        self.assertIn("function consoleLifecycleSupported()", app)
        self.assertIn("return hasCapability('restart_console');", app)
        self.assertIn("restartConsoleBtn.disabled = !lifecycleSupported", app)
        self.assertIn("stopConsoleBtn.disabled = !lifecycleSupported", app)
        self.assertEqual(app.count("if (!consoleLifecycleSupported()) return;"), 2)
        self.assertGreaterEqual(app.count("if (!consoleLifecycleSupported()) {"), 2)

    def test_platform_presentation_comes_from_state(self):
        core = (ROOT / "static/js/core.js").read_text(encoding="utf-8")
        widgets = (ROOT / "static/js/widgets.js").read_text(encoding="utf-8")
        app = (ROOT / "static/app.js").read_text(encoding="utf-8")
        html = (ROOT / "static/index.html").read_text(encoding="utf-8")

        for field in (
            "shortcutModifier",
            "dataDir",
            "logsDir",
            "consoleLogPath",
            "launchInstruction",
            "lifecycleNotice",
        ):
            self.assertIn(field, core)
        self.assertIn("shortcutLabel('K', data)", widgets)
        self.assertIn("shortcutLabel('J', data)", widgets)
        self.assertIn("shortcutLabel('V', data)", widgets)
        self.assertIn("platformPresentation().launchInstruction", app)
        self.assertNotIn("总控台.app", app)
        self.assertNotIn("~/Library", html)
        self.assertNotIn("kill -9", html)

    def test_picker_uses_structured_path_and_command_fields(self):
        overlays = (ROOT / "static/js/overlays.js").read_text(encoding="utf-8")

        self.assertIn("r.commandSpec", overlays)
        self.assertIn("r.platformCompatibility", overlays)
        self.assertIn("r.dir", overlays)
        self.assertIn("r.stem", overlays)
        self.assertNotIn("shellQuotePath", overlays)
        self.assertNotIn("fallbackScriptCommand", overlays)
        self.assertNotIn("split('/')", overlays)
        self.assertNotIn("lastIndexOf('/')", overlays)
        self.assertIn("if (selectedCommandSpec) body.commandSpec", overlays)

        core = (ROOT / "static/js/core.js").read_text(encoding="utf-8")
        services = (ROOT / "static/js/services.js").read_text(encoding="utf-8")
        self.assertNotIn("shortHome", core + services)
        self.assertNotIn("/Users/", core + services)

    def test_lifecycle_and_external_process_actions_are_capability_gated(self):
        app = (ROOT / "static/app.js").read_text(encoding="utf-8")
        launchpad = (ROOT / "static/js/launchpad.js").read_text(encoding="utf-8")
        overlays = (ROOT / "static/js/overlays.js").read_text(encoding="utf-8")
        services = (ROOT / "static/js/services.js").read_text(encoding="utf-8")
        widgets = (ROOT / "static/js/widgets.js").read_text(encoding="utf-8")

        self.assertIn("intent.canManage", app)
        self.assertIn("hasCapability('stop_managed')", app)
        self.assertIn("const capability = starting ? 'launch_managed' : 'stop_managed'", launchpad)
        self.assertIn("diagAttach.hidden = !hasCapability('attach_external')", launchpad)
        self.assertIn("ownerLifecycle.canManage", launchpad)
        self.assertIn(": hasCapability('kill_external')", launchpad)
        self.assertGreaterEqual(overlays.count("hasCapability('kill_external')"), 2)
        self.assertIn("pendingAttach = hasCapability('attach_external')", overlays)
        self.assertIn("r.kill.hidden = !hasCapability('kill_external')", services)
        self.assertIn("if (!hasCapability('kill_external')) return;", services)
        self.assertIn("batchStop.hidden = !canStop", widgets)
        self.assertGreaterEqual(widgets.count("if (!hasCapability('stop_managed'))"), 2)

    def test_phase4_lifecycle_mutations_freeze_generation_and_fail_closed(self):
        app = (ROOT / "static/app.js").read_text(encoding="utf-8")
        core = (ROOT / "static/js/core.js").read_text(encoding="utf-8")
        lifecycle = (ROOT / "static/js/lifecycle.js").read_text(encoding="utf-8")
        launchpad = (ROOT / "static/js/launchpad.js").read_text(encoding="utf-8")
        overlays = (ROOT / "static/js/overlays.js").read_text(encoding="utf-8")
        widgets = (ROOT / "static/js/widgets.js").read_text(encoding="utf-8")

        self.assertIn("return Object.freeze({", lifecycle)
        self.assertIn("expectedGeneration: status === 'stopped' ? null : generation", lifecycle)
        self.assertIn("const hasExplicitStatus", lifecycle)
        self.assertIn("const hasExplicitControl", lifecycle)
        self.assertIn("status === 'orphaned' || status === 'unknown'", lifecycle)
        self.assertIn("const pending = pollPromise", app)
        self.assertIn("if (pending) await pending", app)
        self.assertIn("return poll(true)", app)
        self.assertIn("return Promise.resolve(false)", app)

        self.assertIn("toggleApp(a.id, null, intent)", app)
        self.assertIn("restartAppFromPalette(a.id, intent, name)", app)
        self.assertIn("lifecyclePayload(intent)", app)
        self.assertIn("capturedIntent || lifecycleSnapshot", launchpad)
        self.assertIn("lifecycle.status === 'orphaned'", launchpad)
        self.assertIn("lifecycle.status === 'unknown'", launchpad)
        self.assertIn("lifecycleState === 'unavailable' ? '不可用'", launchpad)
        self.assertIn("lifecyclePayload(intent, starting ? {} : { force: false })", launchpad)
        self.assertIn("del('/api/apps/' + app.id, lifecyclePayload(intent))", launchpad)
        self.assertIn("'/api/apps/' + owner.appId + '/stop'", launchpad)
        self.assertIn("lifecyclePayload(intent, { force: false })", launchpad)

        self.assertIn("body.expectedGeneration = editingAppOriginal.lifecycle.expectedGeneration", overlays)
        self.assertIn("await refreshLifecycleState(app)", overlays)
        self.assertIn("sameLifecycleGeneration(intent, latest, currentPlatform())", overlays)
        self.assertIn("if (!stateIsFresh || !hasCapability('force_stop_managed')", overlays)
        self.assertIn("return stateIsFresh", overlays)
        self.assertIn("lifecyclePayload(forceIntent, { force: true })", overlays)
        self.assertIn("isGenerationMismatch(result)", overlays)
        self.assertIn("item.intent.canManage", widgets)
        self.assertIn("lifecyclePayload(item.intent, { force: false })", widgets)
        self.assertIn("const del = (p, b) => req('DELETE', p, b)", core)

    def test_windows_import_wizard_follows_preview_commit_rollback_contract(self):
        html = (ROOT / "static/index.html").read_text(encoding="utf-8")
        widgets = (ROOT / "static/js/widgets.js").read_text(encoding="utf-8")

        for element_id in (
            "importMask",
            "importSourcePath",
            "importMappingList",
            "importPreview",
            "importCommit",
            "importRollback",
        ):
            self.assertIn(f'id="{element_id}"', html)
        self.assertIn("post('/api/config/import/preview', request)", widgets)
        self.assertIn("post('/api/config/import/commit', request)", widgets)
        self.assertIn("post('/api/config/import/rollback', { importId: importReceiptId })", widgets)
        self.assertIn("new Set(['ready', 'needs_review'])", widgets)
        self.assertIn("checkbox.disabled = !selectable", widgets)
        self.assertIn("selectedAppIds", widgets)
        self.assertIn("platform !== 'windows'", widgets)
        self.assertIn("closeSettingsCenter(false)", widgets)
        self.assertIn("openLayer(importMask, importSourcePath, returnFocus)", widgets)

    def test_windows_font_stack_precedes_macos_fallbacks(self):
        ops = (ROOT / "static/themes/ops.css").read_text(encoding="utf-8")
        font_line = next(line for line in ops.splitlines() if "--font-sans:" in line)
        self.assertLess(font_line.index("'Segoe UI'"), font_line.index("-apple-system"))

    def test_new_port_discovery_is_session_scoped_and_actionable(self):
        html = (ROOT / "static/index.html").read_text(encoding="utf-8")
        services = (ROOT / "static/js/services.js").read_text(encoding="utf-8")
        app = (ROOT / "static/app.js").read_text(encoding="utf-8")

        self.assertIn('id="portDiscovery"', html)
        self.assertIn('id="portDiscoveryList" role="list"', html)
        self.assertIn('aria-live="polite"', html)
        self.assertIn("const discoverySeenKeys = new Set()", services)
        self.assertIn("let discoveryNeedsBaseline = true", services)
        self.assertIn("export function suspendPortDiscovery", services)
        self.assertIn("export function observePortDiscovery", services)
        self.assertIn("svc.instanceKey", services)
        self.assertIn("svc.group === 'mine'", services)
        self.assertIn("!svc.hidden", services)
        self.assertIn("!knownPorts.has(port)", services)
        self.assertIn("if (!app || !app.running) continue", services)
        self.assertIn("app.listening !== false", services)
        self.assertIn("discoveryItems.delete(key)", services)
        self.assertNotIn("present: false", services)
        for label in ("加入启动台", "忽略并隐藏", "暂时关闭"):
            self.assertIn(label, services)
        self.assertIn("observePortDiscovery(data)", app)
        self.assertIn("suspendPortDiscovery()", app)

    def test_port_conflict_dialog_offers_non_destructive_resolution(self):
        html = (ROOT / "static/index.html").read_text(encoding="utf-8")
        launchpad = (ROOT / "static/js/launchpad.js").read_text(encoding="utf-8")

        self.assertIn('id="diagOpen"', html)
        self.assertIn('id="diagEdit"', html)
        self.assertIn("打开占用服务", html)
        self.assertIn("修改当前卡片", html)
        self.assertIn("并不是由这张卡片启动的", launchpad)
        self.assertIn("两张卡片也可以保存相同端口", launchpad)
        self.assertIn("openAppModal(app)", launchpad)

    def test_create_actions_stay_in_launchpad_and_global_palette(self):
        html = (ROOT / "static/index.html").read_text(encoding="utf-8")
        app = (ROOT / "static/app.js").read_text(encoding="utf-8")
        launchpad_start = html.index('id="view-launchpad"')
        services_start = html.index('id="view-services"')
        self.assertIn('id="addSvcCard"', html[launchpad_start:services_start])
        self.assertIn('id="addTaskCard"', html[launchpad_start:services_start])
        self.assertNotIn('id="addSvcCard"', html[services_start:])
        self.assertNotIn('id="addTaskCard"', html[services_start:])
        self.assertIn("title: '添加服务'", app)
        self.assertIn("title: '添加批处理任务'", app)
        self.assertIn("row.tabIndex = -1", app)

    def test_topbar_does_not_duplicate_primary_view_navigation(self):
        html = (ROOT / "static/index.html").read_text(encoding="utf-8")
        app = (ROOT / "static/app.js").read_text(encoding="utf-8")
        widgets = (ROOT / "static/js/widgets.js").read_text(encoding="utf-8")

        self.assertIn('id="rail-launchpad"', html)
        self.assertIn('id="rail-services"', html)
        for obsolete_id in (
            'id="sideNav"',
            'id="tab-launchpad"',
            'id="tab-services"',
        ):
            self.assertNotIn(obsolete_id, html)
        self.assertIn('id="view-launchpad" role="tabpanel" aria-label="启动台"', html)
        self.assertIn('id="view-services" role="tabpanel" aria-label="服务监控"', html)
        for obsolete_binding in (
            "const sideNav",
            "navBtns",
            "navCountLaunch",
            "navCountSvc",
            "navIconLaunch",
            "navIconSvc",
        ):
            self.assertNotIn(obsolete_binding, app)
        self.assertIn("const tab = $('#rail-services')", widgets)
        self.assertNotIn("const tab = $('#tab-services')", widgets)

    def test_command_search_and_quick_actions_share_one_width_track(self):
        ops = (ROOT / "static/themes/ops.css").read_text(encoding="utf-8")
        base = (ROOT / "static/base.css").read_text(encoding="utf-8")

        command_column = theme_block(ops, ".vh-right")
        self.assertIn("width: min(100%, 400px)", command_column)
        self.assertIn("flex: 0 1 400px", command_column)
        self.assertIn("padding-top: 28px", command_column)
        self.assertIn("width: 100%", theme_block(ops, ".cmdk-trigger"))

        actions = theme_block(base, ".quick-actions")
        self.assertIn("display: grid", actions)
        self.assertIn("grid-template-columns: repeat(4, minmax(0, 1fr))", actions)
        self.assertIn("width: 100%", actions)
        self.assertIn("justify-content: center", theme_block(base, ".qa-chip"))
        self.assertRegex(
            ops,
            r"(?s)@media \(max-width: 900px\)\s*\{.*?"
            r"\.vh-right\s*\{[^}]*padding-top:\s*0;",
        )

    def test_service_kpi_sparklines_do_not_change_row_height(self):
        ops = (ROOT / "static/themes/ops.css").read_text(encoding="utf-8")
        base = (ROOT / "static/base.css").read_text(encoding="utf-8")

        kpi = theme_block(ops, ".ov")
        self.assertIn("height: 92px", kpi)
        self.assertNotIn("min-height", kpi)

        spark = theme_block(base, ".spark")
        for declaration in (
            "position: absolute",
            "left: 58px",
            "right: 16px",
            "bottom: 9px",
            "height: 14px",
            "margin: 0",
        ):
            self.assertIn(declaration, spark)

        spark_line = theme_block(base, ".spark polyline")
        self.assertIn("stroke-linecap: round", spark_line)
        self.assertNotIn("stroke-dasharray", spark_line)
        self.assertNotIn("animation:", spark_line)
        self.assertNotIn("@keyframes telemetry-dash", ops)

    def test_launchpad_cards_have_keyboard_sorting_contract(self):
        html = (ROOT / "static/index.html").read_text(encoding="utf-8")
        source = (ROOT / "static/js/launchpad.js").read_text(encoding="utf-8")
        self.assertIn('id="reorderInstructions"', html)
        self.assertIn('id="reorderStatus"', html)
        self.assertIn("card.addEventListener('keydown', cardSortKeyDown)", source)
        self.assertIn("finishKeyboardSort(false)", source)
        self.assertIn("pointercancel', onCancel", source)
        self.assertNotIn("pointercancel', onUp", source)

    def test_add_cards_stay_after_existing_cards(self):
        source = (ROOT / "static/js/launchpad.js").read_text(encoding="utf-8")
        for statement in (
            "svcGrid.append(addSvc)",
            "taskGrid.append(addTask)",
            "programGrid.append(addProgram)",
        ):
            self.assertIn(statement, source)
        for statement in (
            "svcGrid.prepend(addSvc)",
            "taskGrid.prepend(addTask)",
            "programGrid.prepend(addProgram)",
        ):
            self.assertNotIn(statement, source)

    def test_launchpad_cards_expose_runtime_and_privilege_sources(self):
        source = (ROOT / "static/js/launchpad.js").read_text(encoding="utf-8")
        ops = (ROOT / "static/themes/ops.css").read_text(encoding="utf-8")

        self.assertIn("runtimeBadge = el('span', 'runtime-badge')", source)
        for runtime_class in (
            "runtime-managed",
            "runtime-task",
            "runtime-scheduled",
            "runtime-docker",
            "runtime-program",
            "runtime-elevated",
        ):
            self.assertIn("classList.toggle('" + runtime_class + "'", source)
            self.assertIn(".app-card." + runtime_class, ops)
        for label in (
            "本地受管",
            "本地任务",
            "计划任务",
            "Docker",
            "常规启动",
            "管理员启动",
        ):
            self.assertIn(label, source)

    def test_service_load_kpis_name_their_scope_and_deduplicate_pids(self):
        html = (ROOT / "static/index.html").read_text(encoding="utf-8")
        launchpad = (ROOT / "static/js/launchpad.js").read_text(encoding="utf-8")
        services = (ROOT / "static/js/services.js").read_text(encoding="utf-8")

        self.assertEqual(html.count('<div class="ov-label">服务 CPU</div>'), 2)
        self.assertEqual(html.count('<div class="ov-label">服务内存</div>'), 2)
        self.assertNotIn('<div class="ov-label">总 CPU</div>', html)
        self.assertNotIn('<div class="ov-label">总内存</div>', html)
        self.assertIn("const seenPids = new Set()", launchpad)
        self.assertIn("const seenPids = new Set()", services)

    def test_service_cpu_kpis_normalize_for_logical_core_capacity(self):
        launchpad = (ROOT / "static/js/launchpad.js").read_text(encoding="utf-8")
        services = (ROOT / "static/js/services.js").read_text(encoding="utf-8")
        widgets = (ROOT / "static/js/widgets.js").read_text(encoding="utf-8")

        for source in (launchpad, services, widgets):
            self.assertIn("normalizeHostCpuPercent", source)
            self.assertIn("logicalCpuCount", source)
            self.assertIn("navigator.hardwareConcurrency", source)
        self.assertIn("serviceCpuPercent(svc.cpu)", services)
        self.assertIn("serviceCpuPercent(w.cpu)", services)
        self.assertIn("const seenPids = new Set()", widgets)

    def test_optional_appearance_section_and_unified_brand_assets_exist(self):
        html = (ROOT / "static/index.html").read_text(encoding="utf-8")
        overlays = (ROOT / "static/js/overlays.js").read_text(encoding="utf-8")
        css = (ROOT / "static/base.css").read_text(encoding="utf-8")
        self.assertIn('id="appearanceDetails"', html)
        self.assertIn('class="appearance-disclosure-closed">展开设置</span>', html)
        self.assertIn('class="appearance-disclosure-open">收起设置</span>', html)
        self.assertIn('id="appearanceChevron"', html)
        self.assertIn("icon('chevron-down', 16)", overlays)
        self.assertIn(".appearance-details[open] .appearance-chevron", css)
        self.assertIn("transform: rotate(180deg)", css)
        self.assertIn('/assets/brand-mark.png', html)
        self.assertIn('/assets/favicon-32.png', html)
        for name in (
            "brand-mark.png",
            "console-app-icon.png",
            "favicon-32.png",
            "favicon.ico",
            "apple-touch-icon.png",
        ):
            with self.subTest(name=name):
                self.assertTrue((ROOT / "static/assets" / name).is_file())


if __name__ == "__main__":
    unittest.main()
