import { CodeBlock as CodeShineBlock } from '@oxog/codeshine/react'
import { useThemeStore } from '@/hooks/useTheme'
import { cn } from '@/lib/utils'

interface CodeBlockProps {
  code: string
  language?: string
  filename?: string
  lineNumbers?: boolean
  highlightLines?: string
  className?: string
  copyButton?: boolean
  showLanguageBadge?: boolean
  maxHeight?: string
}

export function CodeBlock({
  code,
  language = 'bash',
  filename,
  lineNumbers = true,
  highlightLines,
  className,
  copyButton = true,
  showLanguageBadge = true,
  maxHeight,
}: CodeBlockProps) {
  const resolved = useThemeStore((s) => s.resolved)
  const codeshineTheme = resolved === 'dark' ? 'github-dark' : 'github-light'

  return (
    <div className={cn('codeblock-wrapper', className)}>
      <CodeShineBlock
        code={code.trim()}
        language={language}
        theme={codeshineTheme}
        lineNumbers={lineNumbers}
        highlightLines={highlightLines}
        copyButton={copyButton}
        filename={filename}
        showLanguageBadge={showLanguageBadge}
        maxHeight={maxHeight}
        tabSize={2}
      />
    </div>
  )
}
