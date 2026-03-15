import { CodeBlock as CodeShineBlock } from '@oxog/codeshine/react'
import { useTheme } from '@/hooks/useTheme'
import { cn } from '@/lib/utils'

interface CodeBlockProps {
  code: string
  language?: string
  filename?: string
  lineNumbers?: boolean
  highlightLines?: (number | string)[]
  className?: string
  copyButton?: boolean
}

export function CodeBlock({
  code,
  language = 'bash',
  filename,
  lineNumbers = false,
  highlightLines,
  className,
  copyButton = true,
}: CodeBlockProps) {
  const { theme } = useTheme()
  const codeshineTheme = theme === 'dark' ? 'tokyo-night' : 'github-light'

  return (
    <div className={cn('relative group', className)}>
      <CodeShineBlock
        code={code.trim()}
        language={language}
        theme={codeshineTheme}
        lineNumbers={lineNumbers}
        highlightLines={highlightLines}
        copyButton={copyButton}
        filename={filename}
        wrapLines
      />
    </div>
  )
}
