"""
bot/commands.py — Discord event listeners and slash commands for the setup phase.
 
Covers:
- Welcome message on guild join
- Attachment listener (logs uploads, no analysis yet)
- /help  — describes what scOWL does
- /status — reports bot uptime and basic counters
"""

import discord

from datetime import datetime, timezone
from config import WELCOME_CHANNEL_NAME, WATCHED_CHANNEL_NAMES
from discord.ext import commands
from discord import app_commands, Embed, Interaction

class ScowlEvents(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.start_time = datetime.now(timezone.utc)
        self.watched = (
            " · ".join(f"`#{name}`" for name in WATCHED_CHANNEL_NAMES)
            if WATCHED_CHANNEL_NAMES
            else "All channels"
        )

    @commands.Cog.listener()
    async def on_guild_join(self, guild):
        target_channel = None
        if WELCOME_CHANNEL_NAME:
            target_channel = next(
                (c for c in guild.text_channels if c.name.lower() == WELCOME_CHANNEL_NAME),
                None,
            )
        target_channel = target_channel or guild.system_channel
        if target_channel is not None:
            embed = Embed(
                title="scOWL is watching",
                description=(
                    "Drop any file in a watched channel and scOWL will automatically "
                    "run a static analysis — no commands needed.\n\n"
                    "Supported formats: **PE · ELF · PDF · Office · Scripts**"
                ),
                color=0x5865F2,
            )
            embed.set_author(
                name="Static malware triage",
                icon_url=self.bot.user.avatar.url
            )
            embed.add_field(name="Watching", value=self.watched, inline=False)
            embed.add_field(name="Version", value="v0.1", inline=True)
            embed.add_field(name="Commands", value="`/help` · `/status` · `/scan`", inline=True)
            embed.set_footer(text="scOWL · Use /help for the full command list")
            await target_channel.send(embed=embed)

    @app_commands.command(name="help", description="Overview of scOWL and its analysis capabilities")
    async def help(self, interaction: Interaction):
        embed = Embed(
            title="scOWL — Static malware triage",
            description=(
                "scOWL automatically analyzes every file uploaded in watched channels "
                "and reports a risk score, ATT&CK mapping and VirusTotal reputation.\n\n"
                "You can also trigger a manual scan with `/scan`."
            ),
            color=0x5865F2,
        )
        embed.set_author(name="Help")
        embed.add_field(
            name="Supported formats",
            value="PE · ELF · PDF · Office · PS1 / BAT / VBS / JS",
            inline=False,
        )
        embed.add_field(name="Watching", value=self.watched, inline=False)
        embed.add_field(name="/help", value="This message", inline=True)
        embed.add_field(name="/status", value="Bot uptime and stats", inline=True)
        embed.add_field(name="/scan", value="Manual scan (coming soon)", inline=True)
        embed.add_field(
            name="Source",
            value="[github.com/HalfTimeOfLife/scOWL](https://github.com/HalfTimeOfLife/scOWL)",
            inline=False,
        )
        embed.set_footer(text="scOWL · Static malware triage")
        await interaction.response.send_message(embed=embed)
    
    @app_commands.command(name="status", description="Current bot status and runtime statistics")
    async def status(self, interaction: Interaction):
        uptime = datetime.now(timezone.utc) - self.start_time
        hours, remainder = divmod(int(uptime.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)

        embed = Embed(title="scOWL status", color=0x5865F2)
        embed.set_author(name="Runtime statistics")
        embed.add_field(name="Uptime", value=f"{hours}h {minutes}m {seconds}s", inline=True)
        embed.add_field(name="Latency", value=f"{round(self.bot.latency * 1000)} ms", inline=True)
        embed.add_field(name="Servers", value=str(len(self.bot.guilds)), inline=True)
        embed.add_field(name="Watching", value=self.watched, inline=False)
        embed.add_field(name="Version", value="v0.1", inline=True)
        embed.set_footer(text="scOWL · Use /help for the full command list")
        await interaction.response.send_message(embed=embed)
        

                     
async def setup(bot):
    await bot.add_cog(ScowlEvents(bot))