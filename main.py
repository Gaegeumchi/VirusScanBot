# Discord Security bot 
# Copyright 2024 Gaegeumchi.
import discord
from dotenv import load_dotenv
import os
import requests

load_dotenv()

token = os.environ.get('token')
vtapi = os.environ.get('vtapi')
client = discord.Client(intents=discord.Intents.all())

startemoji = '🔄'

@client.event
async def on_ready():
    print('Login {0.user}'.format(client))

@client.event
async def on_message(message):
    if message.author == client.user:
        return

    if 'https://' in message.content or 'http://' in message.content:
        urls = [word for word in message.content.split() if word.startswith('http://') or word.startswith('https://')]
        
        for user_url in urls:
            url = "https://www.virustotal.com/api/v3/urls"
            headers = {
                "x-apikey": vtapi,
                "accept": "application/json",
                "content-type": "application/x-www-form-urlencoded"
            }
            
            params = {'url': user_url}
            response = requests.post(url, headers=headers, params=params)
            result_json = response.json()
            analysis_id = result_json['data']['id']
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            analysis_response = requests.get(analysis_url, headers=headers)
            analysis_result = analysis_response.json()['data']['attributes']['results']
            detected_engines = [engine for engine, data in analysis_result.items() if data['category'] != 'harmless']
            
            if detected_engines:
                await message.add_reaction('❌')
                await message.channel.send(f"⚠️ Virus detected in {len(detected_engines)} Engines")
                result_json = response.json()
                analysis_id = result_json['data']['id']
                print(f"Analysis ID: {analysis_id}")
                analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                analysis_response = requests.get(analysis_url, headers=headers)
                print(analysis_response.text)
            else:
                await message.add_reaction('✅')
                await message.remove_reaction('🔄', client.user)
                print('Safe URL' + user_url)
                



client.run(token)
