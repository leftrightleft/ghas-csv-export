import os
import requests
import csv

org = os.environ.get('ORG')
user = os.environ.get('USER')
token = os.environ.get('TOKEN')

header = {'Authorization': 'token ' + os.environ['TOKEN']}
ENDPOINT = 'https://api.github.com/'


def build_repo_url() -> str:
    '''
    generate the urls for the api call
    '''
    if org is not None:
        repos_path = f'orgs/{org}/repos?type=public'
        slug = org
    elif user is not None:
        repos_path = f'users/{user}/repos'
        slug = user
    else:
        raise Exception('No org or user specified')
    return f'{ENDPOINT}{repos_path}', slug


def build_alerts_url(slug: str, repo: str) -> str:
    '''
    build the url for the alerts
    '''
    return f'{ENDPOINT}repos/{slug}/{repo}/code-scanning/alerts'


def get_repos(url: str) -> list:
    '''
    get the repos from the api including paging
    '''
    repos = []
    response = requests.get(url, headers={'Authorization': f'token {token}'})
    if response.status_code == 200:
        for repo in response.json():
            repos.append(repo['name'])
    else:
        raise Exception(f'Error: {response.status_code} Body: {response.json()}')

    while 'next' in response.links.keys():
        response = requests.get(response.links['next']['url'], headers=header)
        if response.status_code == 200:
            for repo in response.json():
                repos.append(repo['name'])
        else:
            raise Exception(f'Error: {response.status_code} Body: {response.json()}')
    return repos


def get_alerts(slug: str, repos: list) -> list:
    '''
    get the alerts for each repo
    returns a list of dicts
    '''
    alerts = []
    for repo in repos:
        response = requests.get(build_alerts_url(slug, repo), headers={
                                'Authorization': f'token {token}'})
        if response.status_code == 200:
            alerts.append({'repo': repo, 'alerts': response.json()})
        elif response.status_code == 404:
                pass
        else:
            print(f'Error: {response.status_code} URL:{build_alerts_url(slug, repo)}')
            pass

        while 'next' in response.links.keys():
            response = requests.get(
                response.links['next']['url'], headers=header)
            if response.status_code == 200:
                alerts.append({'repo': repo, 'alerts': response.json()})
            elif response.status_code == 404:
                pass
            else:
                print(f'Error: {response.status_code} URL:{build_alerts_url(slug, repo)}')
                pass
    return alerts


def clean_alert(repo: str, alert: dict) -> list:
    '''
    clean the alert dict
    '''
    return (repo,
            alert['number'],
            alert['created_at'],
            alert['state'],
            alert['html_url'],
            alert['rule']["id"],
            alert['rule'].get(
                "security_severity_level", 'n/a'),
            alert['tool']['name'],
            alert['most_recent_instance']['location']['path'])


def main():
    repos_url, slug = build_repo_url()
    repos = get_repos(repos_url)
    alerts = get_alerts(slug, repos)
    with open('alerts.csv', 'w') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['repo', 'number', 'created at', 'state',
                            'url', 'rule id', 'severity level', 'tool name', 'path'])
        for alert in alerts:
            for a in alert['alerts']:
                writer.writerow(clean_alert(alert['repo'], a))


if __name__ == '__main__':
    main()
