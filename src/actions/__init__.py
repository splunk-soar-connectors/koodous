# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Koodous action registrations."""

from soar_sdk.app import App

from . import detonate_file, get_report, make_request


def register_actions(app: App) -> None:
    """Register the Koodous action handlers on the supplied app."""
    app.register_action(
        detonate_file.detonate_file,
        description="Run the file in the sandbox and retrieve the analysis results",
        action_type="generic",
        read_only=False,
        summary_type=detonate_file.DetonateFileSummary,
        verbose="File detonation may take a while. If the polling in this action doesn't succeed in getting the file analysis (which will be indicated through the <b>analysis_complete</b> key in the summary), then you should continue polling with the <b>get report</b> action. If the <b>analysis_type</b> is 'yara' and <b>force_yara_analysis</b> is false, then the 'yara' analysis will only be performed if it has not been performed before. To perform yara analysis repeatedly, keep <b>force_yara_analysis</b> as true.",
    )
    app.register_action(
        get_report.get_report,
        description="Query for results of an already completed detonation",
        action_type="investigate",
        read_only=True,
        summary_type=get_report.GetReportSummary,
        verbose="Either the <b>sha256</b> or <b>vault_id</b> should be specified. If both are specified, the <b>vault_id</b> parameter will be used. You do not need to be the one who detonated a file to retrieve a report. As long as you know the sha256 (or, have the file in the vault) of the APK you want to analyze, you could run this action. The <b>attempts</b> parameter is how many times this action will poll for analysis results. By default, this number is only 1. If you are polling after <b>detonate file</b> timed out, then you will want to increase this to a higher number. There will be a 30 second interval between each polling attempt.",
    )
    app.make_request()(make_request.make_request)
