import {FilenameFilter} from "../dto/filenameFilter";

export class FilePatternParser {
    private static readonly FILE_PATTERN_SEPARATOR = ',';

    static getNormalizedPatterns(filter: string) {
        return filter.split(FilePatternParser.FILE_PATTERN_SEPARATOR)
            .map(folder => folder.trim())
            .filter(folder => !!folder);
    }

    static parseFilenameFilter(filter: string): FilenameFilter {
        const EXCLUSION_INDICATOR = '!';
        const INCLUDE_ALL = '*';

        const result: FilenameFilter = {
            include: [],
            exclude: []
        };

        // Distribute the patterns from the raw filter string into inclusion or exclusion lists.
        filter.split(FilePatternParser.FILE_PATTERN_SEPARATOR)
            .map(pattern => pattern.trim())
            .forEach(pattern => {
                if (pattern.startsWith(EXCLUSION_INDICATOR)) {
                    const excluded = pattern.substring(EXCLUSION_INDICATOR.length).trim();
                    if (excluded.length) {
                        result.exclude.push(excluded);
                    }
                }
                else if (pattern.length) {
                    result.include.push(pattern);
                }
            });

        if (!result.include.length) {
            // Otherwise no files will be included at all.
            result.include.push(INCLUDE_ALL);
        }

        return result;
    }
}