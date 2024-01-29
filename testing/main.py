import discord
from discord.ext import commands
import youtube_dl

# Enable the necessary intents
intents = discord.Intents.default()
intents.all()

# Set up the bot with a command prefix and intents
bot = commands.Bot(command_prefix='/', intents=intents)

# Function to join a voice channel and play a YouTube video
async def play_youtube(ctx, url):
    channel = ctx.author.voice.channel

    # Connect to the voice channel
    voice_channel = await channel.connect()

    # Download options for youtube_dl
    ydl_opts = {
        'format': 'bestaudio/best',
        'postprocessors': [{
            'key': 'FFmpegExtractAudio',
            'preferredcodec': 'mp3',
            'preferredquality': '192',
        }],
    }

    with youtube_dl.YoutubeDL(ydl_opts) as ydl:
        info_dict = ydl.extract_info(url, download=False)
        url2 = info_dict['formats'][0]['url']
        voice_channel.play(discord.FFmpegPCMAudio(url2), after=lambda e: print('done', e))

# Command to play a YouTube song
@bot.command(name='asculta')
async def asculta(ctx, url):
    print(f"Received /asculta command from {ctx.author}")
    # Check if the user is in a voice channel
    if ctx.author.voice is None or ctx.author.voice.channel is None:
        await ctx.send("You need to be in a voice channel to use this command.")
        return

    # Check if the bot is already in a voice channel
    if ctx.voice_client is not None:
        await ctx.voice_client.disconnect()

    # Call the play_youtube function to join the voice channel and play the YouTube video
    await play_youtube(ctx, url)

# Run the bot with your token
bot.run('MTIwMTIyMDM5MzMwMjc3Mzg2Mg.GSwPbU.XfrFOiBUFmjx4McWn8SoBz-Am3USfTwEncZ_3s')
