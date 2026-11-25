"""
How risky a call is just based on what the tool is capable of. Unknown tools
are treated as high risk (fail closed).
"""

TOOL_RISK: dict[tuple[str, str], float] = {
    ("git", "git_commit"): 0.3,
    ("filesystem", "write_file"): 0.3,
    ("memory", "memory_set"): 0.3,
    ("git", "git_add"): 0.2,
    ("git", "git_init"): 0.2,
}
LOW_RISK_TOOLS = {
    ("filesystem", "read_text_file"), ("filesystem", "list_directory"),
    ("filesystem", "search_files"), ("filesystem", "get_file_info"),
    ("git", "git_status"), ("git", "git_log"), ("git", "git_branch"),
    ("git", "git_diff"), ("git", "git_show_worktree"), ("memory", "memory_get"),
    ("memory", "memory_list"), ("fetch", "list_available_pages"), ("fetch", "fetch")
}
LOW_RISK = 0.05
UNKNOWN_TOOL_RISK = 0.3


def tool_risk(server: str, tool_name: str) -> float:
    if (server, tool_name) in TOOL_RISK:
        return TOOL_RISK[(server, tool_name)]
    if (server, tool_name) in LOW_RISK_TOOLS:
        return LOW_RISK
    return UNKNOWN_TOOL_RISK
