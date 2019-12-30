import {Logger} from "../logger";
import {HttpClient} from "./httpClient";

export class TeamApiClient {
    constructor(private readonly httpClient: HttpClient,
                private readonly log: Logger) {
    }

    async getTeamIdByName(teamName: string) {
        this.log.info(`Resolving team: ${teamName}`);

        const allTeams = await this.httpClient.getRequest('auth/teams') as any[];
        const foundTeam = allTeams.find(team =>
            TeamApiClient.normalizeTeamName(team.fullName) === teamName
        );

        if (foundTeam) {
            this.log.debug(`Resolved team ID: ${foundTeam.id}`);
            return foundTeam.id;
        } else {
            throw Error(`Could not resolve team ID from team name: ${teamName}`);
        }
    }

    /*
        Transforms backslashes to forward slashes.
        Replaces groups of consecutive slashes with a single slash.
        Adds a leading slash if not present.
     */
    static normalizeTeamName(input: string | undefined) {
        const STANDARD_SEPARATOR = '/';

        let result = input || '';

        while (result.includes('\\') || result.includes('//')) {
            result = result
                .replace('\\', STANDARD_SEPARATOR)
                .replace('//', STANDARD_SEPARATOR);
        }

        if (!result.startsWith(STANDARD_SEPARATOR)) {
            result = STANDARD_SEPARATOR + result;
        }
        return result;
    }
}