import * as micromatch from "micromatch";

/**
 * Allows to include/exclude files based on a filter string.
 */
export class FilePathFilter {
    private static readonly fileMatcherOptions = {
        dot: true,   // Match dotfiles.
        // Disable extended functionality that we don't expect in a file filter.
        nobrace: true,
        nobracket: true,
        noextglob: true,
        noglobstar: true,
        noquantifiers: true
    };

    private include: string[] = [];
    private exclude: string[] = [];

    constructor(filter: string) {
        this.parseFilter(filter);

        const INCLUDE_ALL = '*';
        if (!this.include.length) {
            // Otherwise no files will be included at all.
            this.include.push(INCLUDE_ALL);
        }
    }

    includes(path: string) {
        const matchesAnyInclusionPattern = micromatch.any(path, this.include, FilePathFilter.fileMatcherOptions);
        const matchesAnyExclusionPattern = micromatch.any(path, this.exclude, FilePathFilter.fileMatcherOptions);
        return matchesAnyInclusionPattern && !matchesAnyExclusionPattern;
    }

    private parseFilter(filter: string) {
        const FILE_PATTERN_SEPARATOR = ',';
        const EXCLUSION_INDICATOR = '!';

        // Distribute the patterns from the raw filter string into inclusion or exclusion lists.
        filter.split(FILE_PATTERN_SEPARATOR)
            .map(pattern => pattern.trim())
            .forEach(pattern => {
                if (pattern.startsWith(EXCLUSION_INDICATOR)) {
                    const excluded = pattern.substring(EXCLUSION_INDICATOR.length).trim();
                    if (excluded.length) {
                        this.exclude.push(excluded);
                    }
                } else if (pattern.length) {
                    this.include.push(pattern);
                }
            });
    }
}