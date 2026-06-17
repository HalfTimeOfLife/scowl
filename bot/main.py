import asyncio
import discord
from discord.ext import commands
import config

intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True

bot = commands.Bot(command_prefix="!", intents=intents)

@bot.event
async def on_ready():
    await bot.tree.sync()
    print(f"Logged in as {bot.user}")

async def main():
    async with bot:
        await bot.load_extension("bot.commands")
        await bot.start(config.DISCORD_TOKEN)

asyncio.run(main())