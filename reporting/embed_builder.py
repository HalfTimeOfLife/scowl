"""
reporting/embed_builder.py — Discord embed builder for analysis results.

Builds color-coded verdict embeds from AnalysisResult instances.
Fields are only displayed when they contain at least one indicator.
"""

from discord import Embed


def _format_field(indicators, context_key, max_items=10):
    """Format a list of indicators into a Discord embed field value.

    Displays up to max_items entries as inline code blocks, with a
    trailing count if there are more.

    Args:
        indicators: List of Indicator instances to format.
        context_key: Key to extract from each indicator's context dict.
        max_items: Maximum number of items to display (default: 10).

    Returns:
        A newline-separated string of formatted values.
    """
    values = [f"`{i.context[context_key]}`" for i in indicators[:max_items]]
    extra = len(indicators) - max_items
    if extra > 0:
        values.append(f"+ {extra} more...")
    return "\n".join(values)


def build_result_embed(result):
    """Build a Discord embed summarizing an analysis result.

    Verdict and color are determined by the number of indicators:
    - 0 indicators → green, Clean
    - 1–5 indicators → orange, Suspicious
    - 6+ indicators → red, Malicious

    Args:
        result: The AnalysisResult to render.

    Returns:
        A Discord Embed with verdict and per-category indicator fields.
    """
    nb_indicators = len(result.indicators)

    if nb_indicators == 0:
        embed = Embed(
            title="Analysis Result",
            description="✅ Clean — 0 indicator(s)",
            color=0x1AFF00,
        )
        embed.set_author(name="scOWL — Static malware triage")
        embed.add_field(
            name="Details", value="✅ No indicators were found in the analysis."
        )
        return embed
    elif 1 <= nb_indicators <= 5:
        embed = Embed(
            title="Analysis Result",
            description=f"⚠️ Suspicious — {nb_indicators} indicator(s)",
            color=0xFF6A00,
        )
    else:
        embed = Embed(
            title="Analysis Result",
            description=f"🚨 Malicious — {nb_indicators} indicators",
            color=0xFF0000,
        )

    embed.set_author(name="scOWL — Static malware triage")

    urls = [i for i in result.indicators if i.name == "embedded_url"]
    ips = [i for i in result.indicators if i.name == "embedded_ip"]
    downloads = [i for i in result.indicators if i.name == "download_indicator"]
    obfuscation = [i for i in result.indicators if i.name == "obfuscation_indicator"]
    cmdlets = [i for i in result.indicators if i.name == "suspicious_cmdlet"]
    embedded_js = [i for i in result.indicators if i.name == "embedded_javascript"]
    autoopen = [i for i in result.indicators if i.name == "autoopen_action"]
    embedded_files = [i for i in result.indicators if i.name == "embedded_file"]
    objstm = [i for i in result.indicators if i.name == "suspicious_object_stream"]
    malformed = [i for i in result.indicators if i.name == "malformed_structure"]
    extension_mismatch = [
        i for i in result.indicators if i.name == "extension_mimetype_mismatch"
    ]

    if urls:
        embed.add_field(
            name=f"🔗 URLs ({len(urls)})",
            value=_format_field(urls, "url"),
            inline=False,
        )
    if ips:
        embed.add_field(
            name=f"🌐 IPs ({len(ips)})",
            value=_format_field(ips, "ip"),
            inline=False,
        )
    if downloads:
        embed.add_field(
            name=f"⬇️ Downloads ({len(downloads)})",
            value=_format_field(downloads, "pattern"),
            inline=False,
        )
    if obfuscation:
        embed.add_field(
            name=f"🎭 Obfuscation ({len(obfuscation)})",
            value=_format_field(obfuscation, "pattern"),
            inline=False,
        )
    if cmdlets:
        embed.add_field(
            name=f"⚙️ Cmdlets ({len(cmdlets)})",
            value=_format_field(cmdlets, "pattern"),
            inline=False,
        )

    if embedded_js:
        embed.add_field(
            name=f"🧨 Embedded JS ({len(embedded_js)})",
            value=_format_field(embedded_js, "pattern"),
            inline=False,
        )
    if autoopen:
        embed.add_field(
            name=f"▶️ Auto-open actions ({len(autoopen)})",
            value=_format_field(autoopen, "pattern"),
            inline=False,
        )
    if embedded_files:
        embed.add_field(
            name=f"📎 Embedded files ({len(embedded_files)})",
            value=_format_field(embedded_files, "pattern"),
            inline=False,
        )
    if objstm:
        embed.add_field(
            name=f"🗜️ Object streams ({len(objstm)})",
            value=_format_field(objstm, "pattern"),
            inline=False,
        )
    if malformed:
        embed.add_field(
            name=f"🧩 Structure ({len(malformed)})",
            value=_format_field(malformed, "issue"),
            inline=False,
        )

    if extension_mismatch:
        embed.add_field(
            name=f"📄 Extension mismatch ({len(extension_mismatch)})",
            value="\n".join(
                (f"`{i.context['extension']}` → `{i.context['detected_mime_type']}`")
                for i in extension_mismatch
            ),
            inline=False,
        )

    return embed
