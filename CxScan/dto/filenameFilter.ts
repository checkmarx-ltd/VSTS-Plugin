/**
 * Contains lists of wildcards indicating which files to include/exclude from the scan (normally by file extensions).
 * See fileExtension task parameter for more info.
 */
export interface FilenameFilter {
    include: string[],
    exclude: string[]
}