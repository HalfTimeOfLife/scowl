from discord import Embed
from analysis.model import AnalysisResult

def _format_field(indicators, context_key, max_items=10):
    values = [f"`{i.context[context_key]}`" for i in indicators[:max_items]]
    extra = len(indicators) - max_items
    if extra > 0:
        values.append(f"+ {extra} more...")
    return "\n".join(values) if values else "None"

def build_result_embed(result):
    """
    Builds a Discord embed for the given analysis result.

    Args:
        result (AnalysisResult): The analysis result to build the embed for.
        
    Returns:
        Embed: A Discord embed containing the analysis result information.
    """
    nb_indicators = len(result.indicators)
    
    if nb_indicators == 0:
        embed = Embed(title="Analysis Result", description="✅ Clean — 0 indicator(s)", color=0x1AFF00)
        embed.set_author(name="scOWL — Static malware triage")
        embed.add_field(name="Details", value="✅ No indicators were found in the analysis.")
        return embed
    elif 1 <= nb_indicators <= 5:
        embed = Embed(title="Analysis Result", description=f"⚠️ Suspicious — {nb_indicators} indicator(s):", color=0xFF6A00)
    else:
        embed = Embed(title="Analysis Result", description=f"🚨 Malicious — {nb_indicators} indicators", color=0xFF0000)
    
    embed.set_author(name="scOWL — Static malware triage")
    
    urls     = [i for i in result.indicators if i.name == "embedded_url"]
    ips      = [i for i in result.indicators if i.name == "embedded_ip"]
    keywords = [i for i in result.indicators if i.name == "suspicious_keyword"]

    embed.add_field(
        name=f"🔗 URLs ({len(urls)})",
        value=_format_field(urls, "url"),
        inline=False,
    )
    embed.add_field(
        name=f"🌐 IPs ({len(ips)})",
        value=_format_field(ips, "ip"),
        inline=False,
    )
    embed.add_field(
        name=f"🔑 Keywords ({len(keywords)})",
        value=_format_field(keywords, "keyword"),
        inline=False,
    )
    
    return embed
